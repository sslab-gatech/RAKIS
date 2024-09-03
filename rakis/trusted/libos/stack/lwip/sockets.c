/**
 * @file
 * Sockets BSD-Like API module
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 * Improved by Marc Boucher <marc@mbsi.ca> and David Haas <dhaas@alum.rpi.edu>
 *
 */

#include "lwip/opt.h"

#include "lwip/api.h"
#include "lwip/inet.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/raw.h"
#include "lwip/sockets.h"
#include "lwip/udp.h"
#include "lwip/mem.h"

#include "rakis/atomics.h"
#include "rakis/pktq.h"
#include "rakis/stack/rakis_misc.h"
#include "rakis/stack/rakis_spinlock.h"

#include <string.h>

#define RAKIS_BUSYLOOP_RECV 1

#define NUM_SOCKETS 1024
#define UDP_SNDBUF_SIZE 65535

#ifndef set_errno
#define set_errno(err) do { if (err) { RAKIS_GET_THREAD_STRG(rerrno) = (err); } } while(0)
#endif
#define sock_set_errno(e) do { \
  const int sockerr = (e); \
  set_errno(sockerr); \
} while (0)

#define IS_SOCK_ADDR_TYPE_VALID(name)    ((name)->sa_family == AF_INET)
#define IS_SOCK_ADDR_TYPE_VALID_OR_UNSPEC(name)    (((name)->sa_family == AF_UNSPEC) || \
                                                    IS_SOCK_ADDR_TYPE_VALID(name))
#define IS_SOCK_ADDR_ALIGNED(name)      ((((mem_ptr_t)(name)) % 4) == 0)
#define IS_SOCK_ADDR_LEN_VALID(namelen)  ((namelen) == sizeof(struct sockaddr_in))
#define IP4ADDR_PORT_TO_SOCKADDR(sin, ipaddr, port) do { \
      (sin)->sin_family = AF_INET; \
      (sin)->sin_port = lwip_htons((port)); \
      inet_addr_from_ip4addr(&(sin)->sin_addr, ipaddr); \
      memset((sin)->sin_zero, 0, sizeof((sin)->sin_zero)); }while(0)
#define IPADDR_PORT_TO_SOCKADDR(sockaddr, ipaddr, port) \
        IP4ADDR_PORT_TO_SOCKADDR((struct sockaddr_in*)(void*)(sockaddr), ip_2_ip4(ipaddr), port)
#define SOCKADDR4_TO_IP4ADDR_PORT(sin, ipaddr, port) do { \
    inet_addr_to_ip4addr(ip_2_ip4(ipaddr), &((sin)->sin_addr)); \
    (port) = lwip_ntohs((sin)->sin_port); }while(0)
#define SOCKADDR_TO_IPADDR_PORT(sockaddr, ipaddr, port) \
        SOCKADDR4_TO_IP4ADDR_PORT((const struct sockaddr_in*)(const void*)(sockaddr), ipaddr, port)
#define LWIP_SOCKOPT_CHECK_OPTLEN(sock, optlen, opttype) do { if ((optlen) < sizeof(opttype)) { done_socket(sock); return EINVAL; }}while(0)
#define LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, optlen, opttype) do { \
  LWIP_SOCKOPT_CHECK_OPTLEN(sock, optlen, opttype); \
  if ((sock)->conn == NULL) { done_socket(sock); return EINVAL; } }while(0)
#define LWIP_SOCKOPT_CHECK_OPTLEN_CONN_PCB(sock, optlen, opttype) do { \
  LWIP_SOCKOPT_CHECK_OPTLEN(sock, optlen, opttype); \
  if (((sock)->conn == NULL) || ((sock)->conn->pcb.udp == NULL)) { done_socket(sock); return EINVAL; } }while(0)
#define LWIP_SOCKOPT_CHECK_OPTLEN_CONN_PCB_TYPE(sock, optlen, opttype, netconntype) do { \
  LWIP_SOCKOPT_CHECK_OPTLEN_CONN_PCB(sock, optlen, opttype); \
  if (NETCONNTYPE_GROUP(netconn_type((sock)->conn)) != netconntype) { done_socket(sock); return ENOPROTOOPT; } }while(0)
#define LWIP_SO_SNDRCVTIMEO_OPTTYPE struct timeval
#define LWIP_SO_SNDRCVTIMEO_SET_US(optval, val) do { \
  u32_t loc = (val); \
  ((struct timeval *)(optval))->tv_sec = (long)((loc) / 1000000U); \
  ((struct timeval *)(optval))->tv_usec = (long)(((loc) % 1000000U)); }while(0)
#define LWIP_SO_SNDRCVTIMEO_GET_US(optval) ((((const struct timeval *)(optval))->tv_sec * 1000000) + (((const struct timeval *)(optval))->tv_usec))

union sockaddr_aligned {
  struct sockaddr sa;
  struct sockaddr_in sin;
};

/** Contains all internal pointers and states used for a socket */
struct lwip_sock {
  /** sockets currently are built on netconns, each socket has one netconn */
  struct netconn *conn;
  /* counter of how many threads are using a struct lwip_sock (not the 'int') */
  u8_t fd_used;
  /* status of pending close/delete actions */
  u8_t fd_free_pending;
  struct rakis_spinlock fd_lock;
};

static struct lwip_sock sockets[NUM_SOCKETS];
static struct rakis_spinlock poll_lock;
static struct rakis_poll_cb *poll_cb_list;

int sockets_init(void){
  rakis_spinlock_init(&poll_lock);
  return 0;
}

// whether we have a registered poll call for the fd
// called with poll_lock held
static int poll_should_wake(const struct rakis_poll_cb *poll_cb, int fd) {
  nfds_t fdi;
  for (fdi = 0; fdi < poll_cb->poll_nfds; fdi++) {
    const struct pollfd *pollfd = &poll_cb->poll_fds[fdi];
    if (pollfd->fd == fd) {
      if ((pollfd->events & POLLIN) != 0) {
        return 1;
      }
    }
  }
  return 0;
}

// checks if any poll calls are waiting on the fd
// and wakes them up if so
static void poll_check_waiters(int fd) {
  RAKIS_SLOCK(&poll_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_poll_cb_lock));
  struct rakis_poll_cb *poll_cb;

  for (poll_cb = poll_cb_list; poll_cb != NULL; poll_cb = poll_cb->next) {
    if (poll_should_wake(poll_cb, fd)){
      RAKIS_SET_ATOMIC(&poll_cb->notify_mem, true);
    }
  }
  RAKIS_SUNLOCK(&poll_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_poll_cb_lock));
}

// deletes an conn
void static netconn_delete(struct netconn *conn) {
  u8_t prev_flags = RAKIS_EXCHANGE_ATOMIC(&conn->flags_atm, NETCONN_FLAG_MBOXINVALID);

  // we already about to delete this socket
  LWIP_ASSERT("some other thread raced us to delete this conn",
      !(prev_flags & NETCONN_FLAG_MBOXINVALID));

  if (conn->pcb.udp != NULL) {
    switch (NETCONNTYPE_GROUP(conn->type)) {
      case NETCONN_RAW:
        raw_remove(conn->pcb.raw);
        break;
      case NETCONN_UDP:
        conn->pcb.udp->recv_arg = NULL;
        udp_remove(conn->pcb.udp);
        break;
    }
    conn->pcb.udp = NULL;
  }

  pktq_free_queue_pbufs_unlocked(conn->recvq);
#ifndef RAKIS_BUSYLOOP_RECV
  // this should also wake all waiters
  rakis_event_destroy(conn->recvevent);
#endif
  API_RECV_EVENT(conn);
  mem_free(conn);
}

static int sock_inc_used(struct lwip_sock *sock){
  LWIP_ASSERT("sock != NULL", sock != NULL);

  RAKIS_SLOCK(&sock->fd_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_fd_lock));
  if (sock->fd_free_pending){
    RAKIS_SUNLOCK(&sock->fd_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_fd_lock));
    return 0;
  }

  sock->fd_used++;
  RAKIS_SUNLOCK(&sock->fd_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_fd_lock));
  return 1;
}

static void done_socket(struct lwip_sock *sock){
  LWIP_ASSERT("sock != NULL", sock != NULL);

  // if we are the last to use the socket, and a free is pending, free it now
  RAKIS_SLOCK(&sock->fd_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_fd_lock));
  if (--sock->fd_used == 0 &&
      sock->fd_free_pending) {

    struct netconn* conn = sock->conn;
    if (conn != NULL) {
      netconn_delete(conn);
      sock->conn = NULL;
    }
  }
  RAKIS_SUNLOCK(&sock->fd_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_fd_lock));
}

static struct lwip_sock * tryget_socket_unconn_nouse(int fd) {
  int s = fd - LWIP_SOCKET_OFFSET;
  if ((s < 0) || (s >= NUM_SOCKETS)) {
    LWIP_DEBUGF(SOCKETS_DEBUG, ("tryget_socket_unconn(%d): invalid\n", fd));
    return NULL;
  }
  return &sockets[s];
}

static struct lwip_sock * tryget_socket_unconn(int fd) {
  struct lwip_sock *ret = tryget_socket_unconn_nouse(fd);
  if (ret != NULL) {
    if (!sock_inc_used(ret)) {
      return NULL;
    }
  }
  return ret;
}

static struct lwip_sock * tryget_socket(int fd) {
  struct lwip_sock *sock = tryget_socket_unconn(fd);
  if (sock != NULL) {
    if (sock->conn) {
      return sock;
    }
    done_socket(sock);
  }
  return NULL;
}

static struct lwip_sock * get_socket(int fd) {
  struct lwip_sock *sock = tryget_socket(fd);
  if (!sock) {
    if ((fd < LWIP_SOCKET_OFFSET) || (fd >= (LWIP_SOCKET_OFFSET + NUM_SOCKETS))) {
      LWIP_DEBUGF(SOCKETS_DEBUG, ("get_socket(%d): invalid\n", fd));
    }
    set_errno(EBADF);
    return NULL;
  }
  return sock;
}

static void recv_event_callback(struct netconn *conn) {
  int fd;

  if(!conn) {
    return;
  }

  fd = conn->socket;
  LWIP_ASSERT("s >= 0", fd >= 0);
  poll_check_waiters(fd);
}

static struct netconn * netconn_alloc(enum netconn_type t) {
  struct netconn *conn;

  conn = (struct netconn *)mem_malloc(sizeof(struct netconn));
  if (conn == NULL) {
    return NULL;
  }

  if(!pktq_new(&conn->recvq, 2048)){
    log_error("RAKIS Failed to initialize incoming packets queue for lwip socket");
    mem_free(conn);
    return NULL;
  }

  conn->type                      = t;
  conn->pcb.udp                   = NULL;
  conn->socket                    = -1;
  conn->callback                  = recv_event_callback;
  conn->send_timeout_atm          = 0;
  conn->recv_timeout_atm          = 0;
  conn->recv_bufsize_atm          = RECV_BUFSIZE_DEFAULT;
  conn->recv_avail_atm            = 0;
  conn->linger_atm                = -1;
  conn->flags_atm                 = 0;

#ifndef RAKIS_BUSYLOOP_RECV
  conn->recvevent                 = rakis_event_create();
#else
  conn->recvevent                 = NULL;
#endif

  return conn;
}

static u8_t recv_raw_callback(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *src_addr){
  struct pbuf *q;
  struct netconn *conn;

  conn = (struct netconn *)arg;
  if (conn == NULL) {
    return 0;
  }

  if (RAKIS_GET_ATOMIC(&conn->flags_atm) & NETCONN_FLAG_MBOXINVALID) {
    return 0;
  }

  int recv_avail, recv_bufsize;
  recv_bufsize = RAKIS_GET_ATOMIC(&conn->recv_bufsize_atm);
  recv_avail = RAKIS_ADD_ATOMIC(&conn->recv_avail_atm, (int)(p->tot_len));
  if (recv_avail > recv_bufsize) {
    RAKIS_SUB_ATOMIC(&conn->recv_avail_atm, (int)(p->tot_len));
    return 0;
  }

  q = pbuf_clone(PBUF_RAW, p);
  if (q == NULL) {
    RAKIS_SUB_ATOMIC(&conn->recv_avail_atm, (int)(p->tot_len));
    return 0;
  }

  ip_addr_copy(q->net_ip_addr, *src_addr);
  q->net_port = pcb->protocol;

  pktq_enqueue_override_pbuf_unlocked(conn->recvq, q);
#ifndef RAKIS_BUSYLOOP_RECV
  rakis_event_set(conn->recvevent);
#endif
  API_RECV_EVENT(conn);
  return 0;
}

static void recv_udp_callback(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port){
  LWIP_UNUSED_ARG(pcb);
  struct netconn *conn;

  conn = (struct netconn *)arg;
  if (conn == NULL) {
    pbuf_free(p);
    return;
  }

  if (RAKIS_GET_ATOMIC(&conn->flags_atm) & NETCONN_FLAG_MBOXINVALID) {
    pbuf_free(p);
    return;
  }

  int recv_avail, recv_bufsize;
  recv_bufsize = RAKIS_GET_ATOMIC(&conn->recv_bufsize_atm);
  recv_avail = RAKIS_ADD_ATOMIC(&conn->recv_avail_atm, (int)(p->tot_len));
  if (recv_avail > recv_bufsize) {
    RAKIS_SUB_ATOMIC(&conn->recv_avail_atm, (int)(p->tot_len));
    pbuf_free(p);
    return;
  }

  ip_addr_set(&p->net_ip_addr, addr);
  p->net_port = port;

  pktq_enqueue_override_pbuf_unlocked(conn->recvq, p);
#ifndef RAKIS_BUSYLOOP_RECV
  rakis_event_set(conn->recvevent);
#endif
  API_RECV_EVENT(conn);
  RAKIS_STAT_INC(sockets_udp_callback_recv_pbuf);
}

static err_t pcb_new(struct netconn *conn, u8_t proto){
  switch (NETCONNTYPE_GROUP(conn->type)) {
    case NETCONN_RAW:
      conn->pcb.raw = raw_new_ip_type(IPADDR_TYPE_V4, proto);
      if (conn->pcb.raw != NULL) {
        raw_set_recv_callback(conn->pcb.raw, recv_raw_callback, conn);
        return ERR_OK;
      }
      break;
    case NETCONN_UDP:
      conn->pcb.udp = udp_new_ip_type(IPADDR_TYPE_V4);
      if (conn->pcb.udp != NULL) {
        udp_set_recv_callback(conn->pcb.udp, recv_udp_callback, conn);
        return ERR_OK;
      }
      break;
    default:
      // Unsupported netconn type, e.g. protocol disabled
      return ERR_VAL;
  }

  return ERR_MEM;
}

static struct netconn * netconn_new(enum netconn_type t, u8_t proto) {
  struct netconn *conn = netconn_alloc(t);
  if (conn == NULL) {
    return NULL;
  }

  err_t err;
  err = pcb_new(conn, proto);
  if (err != ERR_OK) {
#ifndef RAKIS_BUSYLOOP_RECV
    rakis_event_destroy(conn->recvevent);
#endif
    mem_free(conn);
    return NULL;
  }

  return conn;
}

static int alloc_socket(struct netconn *newconn) {
  int i;
  for (i = 0; i < NUM_SOCKETS; ++i) {
    struct lwip_sock *sock = &sockets[i];
    RAKIS_SLOCK(&sock->fd_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_fd_lock));
    if(sock->fd_used == 0 &&
        sock->conn == NULL){

      sock->conn = newconn;
      sock->fd_used = 1;
      sock->fd_free_pending = 0;

      RAKIS_SUNLOCK(&sock->fd_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_fd_lock));
      return i + LWIP_SOCKET_OFFSET;
    }
    RAKIS_SUNLOCK(&sock->fd_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_fd_lock));
  }

  return -1;
}

int lwip_socket(int domain, int type, int protocol) {
  struct netconn *conn;
  int i;

  LWIP_UNUSED_ARG(domain); /* @todo: check this */

  /* create a netconn */
  switch (type) {
    case SOCK_RAW:
      conn = netconn_new(NETCONN_RAW,
             (u8_t)protocol);
      LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_RAW, %d) = ",
                                  domain == PF_INET ? "PF_INET" : "UNKNOWN", protocol));
      break;
    case SOCK_DGRAM:
      conn = netconn_new(NETCONN_UDP, 0);
      LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_DGRAM, %d) = ",
                                  domain == PF_INET ? "PF_INET" : "UNKNOWN", protocol));
      break;
    default:
      LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%d, %d/UNKNOWN, %d) = -1\n",
                                  domain, type, protocol));
      set_errno(EINVAL);
      return -1;
  }

  if (!conn) {
    LWIP_DEBUGF(SOCKETS_DEBUG, ("-1 / ENOBUFS (could not create netconn)\n"));
    set_errno(ENOBUFS);
    return -1;
  }

  i = alloc_socket(conn);

  if (i == -1) {
    netconn_delete(conn);
    set_errno(ENFILE);
    return -1;
  }

  conn->socket = i;
  done_socket(&sockets[i - LWIP_SOCKET_OFFSET]);
  LWIP_DEBUGF(SOCKETS_DEBUG, ("%d\n", i));
  set_errno(0);
  return i;
}

int lwip_close(int s) {
  struct lwip_sock *sock;

  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_close(%d)\n", s));

  sock = get_socket(s);
  if (!sock) {
    return -1;
  }

  LWIP_ASSERT("sock->conn != NULL", sock->conn != NULL);

  RAKIS_SLOCK(&sock->fd_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_fd_lock));
  netconn_delete(sock->conn);
  sock->conn = NULL;

  if (--sock->fd_used > 0){
    sock->fd_free_pending = 1;
  }

  RAKIS_SUNLOCK(&sock->fd_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_fd_lock));
  set_errno(0);
  return 0;
}

static err_t netconn_disconnect(struct netconn *conn){

  if (NETCONNTYPE_GROUP(conn->type) == NETCONN_UDP) {
    udp_disconnect(conn->pcb.udp);
    return ERR_OK;
  }

  return ERR_VAL;
}

static err_t netconn_connect(struct netconn *conn, const ip_addr_t *addr, u16_t port) {
  err_t err;

  if (conn->pcb.udp == NULL) {
    /* This may happen when calling netconn_connect() a second time */
    err = ERR_CLSD;
  } else {
    switch (NETCONNTYPE_GROUP(conn->type)) {
      case NETCONN_RAW:
        err = raw_connect(conn->pcb.raw, addr);
        break;
      case NETCONN_UDP:
        err = udp_connect(conn->pcb.udp, addr, port);
        break;
      default:
        LWIP_ERROR("Invalid netconn type", 0, do {
          err = ERR_VAL;
        } while (0));
        break;
    }
  }

  return err;
}

static err_t netconn_bind(struct netconn *conn, const ip_addr_t *addr, u16_t port){
  err_t err = ERR_VAL;

  if (conn->pcb.ip != NULL) {
    switch (NETCONNTYPE_GROUP(conn->type)) {
      case NETCONN_RAW:
        err = raw_bind(conn->pcb.raw, addr);
        break;
      case NETCONN_UDP:
        err = udp_bind(conn->pcb.udp, addr, port);
        break;
    }
  }

  return err;
}

int lwip_bind(int s, const struct sockaddr *name, socklen_t namelen) {
  struct lwip_sock *sock;
  ip_addr_t local_addr;
  u16_t local_port;
  err_t err;

  sock = get_socket(s);
  if (!sock) {
    return -1;
  }

  /* check size, family and alignment of 'name' */
  LWIP_ERROR("lwip_bind: invalid address", (IS_SOCK_ADDR_LEN_VALID(namelen) &&
             IS_SOCK_ADDR_TYPE_VALID(name) && IS_SOCK_ADDR_ALIGNED(name)),
             sock_set_errno(err_to_errno(ERR_ARG)); done_socket(sock); return -1;);
  LWIP_UNUSED_ARG(namelen);

  SOCKADDR_TO_IPADDR_PORT(name, &local_addr, local_port);
  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_bind(%d, addr=", s));
  ip_addr_debug_print_val(SOCKETS_DEBUG, local_addr);
  LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%"U16_F")\n", local_port));

  err = netconn_bind(sock->conn, &local_addr, local_port);

  if (err != ERR_OK) {
    LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_bind(%d) failed, err=%d\n", s, err));
    sock_set_errno(err_to_errno(err));
    done_socket(sock);
    return -1;
  }

  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_bind(%d) succeeded\n", s));
  sock_set_errno(0);
  done_socket(sock);
  return 0;
}

int lwip_connect(int s, const struct sockaddr *name, socklen_t namelen) {
  struct lwip_sock *sock;
  err_t err;

  sock = get_socket(s);
  if (!sock) {
    return -1;
  }

  if (name->sa_family == AF_UNSPEC) {
    LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d, AF_UNSPEC)\n", s));
    LWIP_ERROR("netconn_disconnect: invalid conn", (sock->conn != NULL), return ERR_ARG;);
    err = netconn_disconnect(sock->conn);
  } else {
    ip_addr_t remote_addr;
    u16_t remote_port;

    /* check size, family and alignment of 'name' */
    LWIP_ERROR("lwip_connect: invalid address", IS_SOCK_ADDR_LEN_VALID(namelen) &&
               IS_SOCK_ADDR_TYPE_VALID_OR_UNSPEC(name) && IS_SOCK_ADDR_ALIGNED(name),
               sock_set_errno(err_to_errno(ERR_ARG)); done_socket(sock); return -1;);

    SOCKADDR_TO_IPADDR_PORT(name, &remote_addr, remote_port);
    LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d, addr=", s));
    ip_addr_debug_print_val(SOCKETS_DEBUG, remote_addr);
    LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%"U16_F")\n", remote_port));

    err = netconn_connect(sock->conn, &remote_addr, remote_port);
  }

  if (err != ERR_OK) {
    LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d) failed, err=%d\n", s, err));
    sock_set_errno(err_to_errno(err));
    done_socket(sock);
    return -1;
  }

  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d) succeeded\n", s));
  sock_set_errno(0);
  done_socket(sock);
  return 0;
}

static int lwip_sockopt_to_ipopt(int optname) {
  /* Map SO_* values to our internal SOF_* values
   * We should not rely on #defines in socket.h
   * being in sync with ip.h.
   */
  switch (optname) {
  case SO_BROADCAST:
    return SOF_BROADCAST;
  case SO_KEEPALIVE:
    return SOF_KEEPALIVE;
  case SO_REUSEADDR:
    return SOF_REUSEADDR;
  default:
    LWIP_ASSERT("Unknown socket option", 0);
    return 0;
  }
}

static int lwip_getsockopt_impl(int s, int level, int optname, void *optval, socklen_t *optlen){
  int err = 0;
  struct lwip_sock *sock = tryget_socket(s);
  if (!sock) {
    return EBADF;
  }

  switch (level) {
    /* Level: SOL_SOCKET */
    case SOL_SOCKET:
      switch (optname) {
        /* The option flags */
        case SO_BROADCAST:
        case SO_KEEPALIVE:
        case SO_REUSEADDR:
          if ((optname == SO_BROADCAST) &&
              (NETCONNTYPE_GROUP(sock->conn->type) != NETCONN_UDP)) {
            done_socket(sock);
            return ENOPROTOOPT;
          }

          optname = lwip_sockopt_to_ipopt(optname);

          LWIP_SOCKOPT_CHECK_OPTLEN_CONN_PCB(sock, *optlen, int);
          *(int *)optval = ip_get_option(sock->conn->pcb.ip, optname);
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, optname=0x%x, ..) = %s\n",
                                      s, optname, (*(int *)optval ? "on" : "off")));
          break;

        case SO_TYPE:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, *optlen, int);
          switch (NETCONNTYPE_GROUP(netconn_type(sock->conn))) {
            case NETCONN_RAW:
              *(int *)optval = SOCK_RAW;
              break;
            case NETCONN_UDP:
              *(int *)optval = SOCK_DGRAM;
              break;
            default: /* unrecognized socket type */
              *(int *)optval = netconn_type(sock->conn);
              LWIP_DEBUGF(SOCKETS_DEBUG,
                          ("lwip_getsockopt(%d, SOL_SOCKET, SO_TYPE): unrecognized socket type %d\n",
                           s, *(int *)optval));
          }  /* switch (netconn_type(sock->conn)) */
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, SO_TYPE) = %d\n",
                                      s, *(int *)optval));
          break;

        case SO_ERROR:
          LWIP_SOCKOPT_CHECK_OPTLEN(sock, *optlen, int);
          *(int *)optval = err_to_errno(ERR_OK);
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, SO_ERROR) = %d\n",
                                      s, *(int *)optval));
          break;

        case SO_SNDTIMEO:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, *optlen, LWIP_SO_SNDRCVTIMEO_OPTTYPE);
          LWIP_SO_SNDRCVTIMEO_SET_US(optval, netconn_get_sendtimeout(sock->conn));
          break;
        case SO_RCVTIMEO:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, *optlen, LWIP_SO_SNDRCVTIMEO_OPTTYPE);
          LWIP_SO_SNDRCVTIMEO_SET_US(optval, netconn_get_recvtimeout(sock->conn));
          break;
        case SO_RCVBUF:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, *optlen, int);
          *(int *)optval = netconn_get_recvbufsize(sock->conn);
          break;
        case SO_SNDBUF:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, *optlen, int);
          *(int *)optval = UDP_SNDBUF_SIZE;
          break;
        case SO_LINGER: {
          s16_t conn_linger;
          struct linger *linger = (struct linger *)optval;
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, *optlen, struct linger);
          conn_linger = RAKIS_GET_ATOMIC(&sock->conn->linger_atm);
          if (conn_linger >= 0) {
            linger->l_onoff = 1;
            linger->l_linger = (int)conn_linger;
          } else {
            linger->l_onoff = 0;
            linger->l_linger = 0;
          }
        }
        break;
        case SO_NO_CHECK:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN_PCB_TYPE(sock, *optlen, int, NETCONN_UDP);
          *(int *)optval = udp_is_flag_set(sock->conn->pcb.udp, UDP_FLAGS_NOCHKSUM) ? 1 : 0;
          break;
        default:
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, UNIMPL: optname=0x%x, ..)\n",
                                      s, optname));
          err = ENOPROTOOPT;
          break;
      }  /* switch (optname) */
      break;

    /* Level: IPPROTO_IP */
    case IPPROTO_IP:
      switch (optname) {
        case IP_TTL:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN_PCB(sock, *optlen, int);
          *(int *)optval = RAKIS_GET_ATOMIC(&(sock->conn->pcb.ip->ttl_atm));
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_IP, IP_TTL) = %d\n",
                                      s, *(int *)optval));
          break;
        case IP_TOS:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN_PCB(sock, *optlen, int);
          *(int *)optval = RAKIS_GET_ATOMIC(&(sock->conn->pcb.ip->tos_atm));
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_IP, IP_TOS) = %d\n",
                                      s, *(int *)optval));
          break;
        default:
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_IP, UNIMPL: optname=0x%x, ..)\n",
                                      s, optname));
          err = ENOPROTOOPT;
          break;
      }  /* switch (optname) */
      break;

    default:
      LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, level=0x%x, UNIMPL: optname=0x%x, ..)\n",
                                  s, level, optname));
      err = ENOPROTOOPT;
      break;
  } /* switch (level) */

  done_socket(sock);
  return err;
}

int lwip_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen) {
  int err;
  struct lwip_sock *sock = get_socket(s);

  if (!sock) {
    return -1;
  }

  if ((NULL == optval) || (NULL == optlen)) {
    sock_set_errno(EFAULT);
    done_socket(sock);
    return -1;
  }

  err = lwip_getsockopt_impl(s, level, optname, optval, optlen);

  sock_set_errno(err);
  done_socket(sock);
  return err ? -1 : 0;
}

static int lwip_setsockopt_impl(int s, int level, int optname, const void *optval, socklen_t optlen){
  int err = 0;
  struct lwip_sock *sock = tryget_socket(s);
  if (!sock) {
    return EBADF;
  }

  switch (level) {

    /* Level: SOL_SOCKET */
    case SOL_SOCKET:
      switch (optname) {

        /* SO_ACCEPTCONN is get-only */

        /* The option flags */
        case SO_BROADCAST:
        case SO_KEEPALIVE:
        case SO_REUSEADDR:
          if ((optname == SO_BROADCAST) &&
              (NETCONNTYPE_GROUP(sock->conn->type) != NETCONN_UDP)) {
            done_socket(sock);
            return ENOPROTOOPT;
          }

          optname = lwip_sockopt_to_ipopt(optname);

          LWIP_SOCKOPT_CHECK_OPTLEN_CONN_PCB(sock, optlen, int);
          if (*(const int *)optval) {
            ip_set_option(sock->conn->pcb.ip, optname);
          } else {
            ip_reset_option(sock->conn->pcb.ip, optname);
          }
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, SOL_SOCKET, optname=0x%x, ..) -> %s\n",
                                      s, optname, (*(const int *)optval ? "on" : "off")));
          break;

          /* SO_TYPE is get-only */
          /* SO_ERROR is get-only */

        case SO_SNDTIMEO: {
          u64_t us_long;
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, optlen, LWIP_SO_SNDRCVTIMEO_OPTTYPE);
          us_long = LWIP_SO_SNDRCVTIMEO_GET_US(optval);
          netconn_set_sendtimeout(sock->conn, us_long);
          break;
        }
        case SO_RCVTIMEO: {
          u64_t us_long;
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, optlen, LWIP_SO_SNDRCVTIMEO_OPTTYPE);
          us_long = LWIP_SO_SNDRCVTIMEO_GET_US(optval);
          netconn_set_recvtimeout(sock->conn, us_long);
          break;
        }
        case SO_RCVBUF:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, optlen, int);
          netconn_set_recvbufsize(sock->conn, *(const int *)optval);
          break;
        case SO_LINGER: {
          const struct linger *linger = (const struct linger *)optval;
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, optlen, struct linger);
          if (linger->l_onoff) {
            int lingersec = linger->l_linger;
            if (lingersec < 0) {
              done_socket(sock);
              return EINVAL;
            }
            if (lingersec > 0xFFFF) {
              lingersec = 0xFFFF;
            }
            RAKIS_SET_ATOMIC(&sock->conn->linger_atm, (s16_t)lingersec);
          } else {
            RAKIS_SET_ATOMIC(&sock->conn->linger_atm, -1);
          }
        }
        break;
        case SO_NO_CHECK:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN_PCB_TYPE(sock, optlen, int, NETCONN_UDP);
          if (*(const int *)optval) {
            udp_set_flags(sock->conn->pcb.udp, UDP_FLAGS_NOCHKSUM);
          } else {
            udp_clear_flags(sock->conn->pcb.udp, UDP_FLAGS_NOCHKSUM);
          }
          break;
        case SO_BINDTODEVICE: {
          const struct ifreq *iface;
          struct netif *n = NULL;

          LWIP_SOCKOPT_CHECK_OPTLEN_CONN(sock, optlen, struct ifreq);

          iface = (const struct ifreq *)optval;
          if (iface->ifr_name[0] != 0) {
            n = netif_find(iface->ifr_name);
            if (n == NULL) {
              done_socket(sock);
              return ENODEV;
            }
          }

          switch (NETCONNTYPE_GROUP(netconn_type(sock->conn))) {
            case NETCONN_UDP:
              udp_bind_netif(sock->conn->pcb.udp, n);
              break;
            case NETCONN_RAW:
              raw_bind_netif(sock->conn->pcb.raw, n);
              break;
            default:
              LWIP_ASSERT("Unhandled netconn type in SO_BINDTODEVICE", 0);
              break;
          }
        }
        break;
        default:
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, SOL_SOCKET, UNIMPL: optname=0x%x, ..)\n",
                                      s, optname));
          err = ENOPROTOOPT;
          break;
      }  /* switch (optname) */
      break;

    /* Level: IPPROTO_IP */
    case IPPROTO_IP:
      switch (optname) {
        case IP_TTL:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN_PCB(sock, optlen, int);
          RAKIS_SET_ATOMIC(&(sock->conn->pcb.ip->ttl_atm), (u8_t)(*(const int *)optval));
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IP, IP_TTL, ..) -> %d\n",
                                      s, RAKIS_GET_ATOMIC(&sock->conn->pcb.ip->ttl_atm)));
          break;
        case IP_TOS:
          LWIP_SOCKOPT_CHECK_OPTLEN_CONN_PCB(sock, optlen, int);
          RAKIS_SET_ATOMIC(&(sock->conn->pcb.ip->tos_atm), (u8_t)(*(const int *)optval));
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IP, IP_TOS, ..)-> %d\n",
                                      s, RAKIS_GET_ATOMIC(&sock->conn->pcb.ip->tos_atm)));
          break;
        default:
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IP, UNIMPL: optname=0x%x, ..)\n",
                                      s, optname));
          err = ENOPROTOOPT;
          break;
      }  /* switch (optname) */
      break;

    default:
      LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, level=0x%x, UNIMPL: optname=0x%x, ..)\n",
                                  s, level, optname));
      err = ENOPROTOOPT;
      break;
  }  /* switch (level) */

  done_socket(sock);
  return err;
}

int lwip_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen) {
  int err = 0;
  struct lwip_sock *sock = get_socket(s);

  if (!sock) {
    return -1;
  }

  if (NULL == optval) {
    sock_set_errno(EFAULT);
    done_socket(sock);
    return -1;
  }

  err = lwip_setsockopt_impl(s, level, optname, optval, optlen);

  sock_set_errno(err);
  done_socket(sock);
  return err ? -1 : 0;
}

int lwip_ioctl(int s, long cmd, void *argp) {
  struct lwip_sock *sock = get_socket(s);
  u8_t val;

  if (!sock) {
    return -1;
  }

  switch (cmd) {
    case FIONREAD:{
      if (!argp) {
        sock_set_errno(EINVAL);
        done_socket(sock);
        return -1;
      }
      
      if(sock->conn == NULL){
        sock_set_errno(EBADF);
        done_socket(sock);
        return -1;
      }

      if (NETCONNTYPE_GROUP(netconn_type(sock->conn)) == NETCONN_INVALID){
        sock_set_errno(EINVAL);
        done_socket(sock);
        return -1;
      }

      struct pktq* recvq = sock->conn->recvq;
      u32 plen = 0;
      RAKIS_SLOCK(&recvq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
      if (pktq_can_dequeue_cons_locked(recvq) > 0){
        struct pbuf* p = pktq_dequeue_peek_cons_locked(recvq);
        plen = p->tot_len;
      }
      RAKIS_SUNLOCK(&recvq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
      *((int *)argp) = plen;
      done_socket(sock);
      return 0;
    }

    case (long)FIONBIO:{
      val = 0;
      if (argp && *(int *)argp) {
        val = 1;
      }
      netconn_set_nonblocking(sock->conn, val);
      LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, FIONBIO, %d)\n", s, val));
      sock_set_errno(0);
      done_socket(sock);
      return 0;
      }

    default:
      break;
  }

  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, UNIMPL: 0x%lx, %p)\n", s, cmd, argp));
  sock_set_errno(ENOSYS); /* not yet implemented */
  done_socket(sock);
  return -1;
}

int lwip_fcntl(int s, int cmd, int val) {
  struct lwip_sock *sock = get_socket(s);
  int ret = -1;
  int op_mode = 0;

  if (!sock) {
    return -1;
  }

  switch (cmd) {
    case F_GETFL:
      ret = netconn_is_nonblocking(sock->conn) ? O_NONBLOCK : 0;
      sock_set_errno(0);
      op_mode |= O_RDWR;

      /* ensure O_RDWR for (O_RDONLY|O_WRONLY) != O_RDWR cases */
      ret |= (op_mode == (O_RDONLY | O_WRONLY)) ? O_RDWR : op_mode;
      break;

    case F_SETFL:
      /* Bits corresponding to the file access mode and the file creation flags [..] that are set in arg shall be ignored */
      val &= ~(O_RDONLY | O_WRONLY | O_RDWR);
      if ((val & ~O_NONBLOCK) == 0) {
        /* only O_NONBLOCK, all other bits are zero */
        netconn_set_nonblocking(sock->conn, val & O_NONBLOCK);
        ret = 0;
        sock_set_errno(0);
      } else {
        sock_set_errno(ENOSYS); /* not yet implemented */
      }
      break;

    default:
      LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_fcntl(%d, UNIMPL: %d, %d)\n", s, cmd, val));
      sock_set_errno(ENOSYS); /* not yet implemented */
      break;
  }

  done_socket(sock);
  return ret;
}

static err_t netconn_getaddr(struct netconn *conn, ip_addr_t *addr, u16_t *port, u8_t local){
  LWIP_ERROR("netconn_getaddr: invalid conn", (conn != NULL), return ERR_ARG;);
  LWIP_ERROR("netconn_getaddr: invalid addr", (addr != NULL), return ERR_ARG;);
  LWIP_ERROR("netconn_getaddr: invalid port", (port != NULL), return ERR_ARG;);

  if (conn->pcb.ip == NULL) {
    return ERR_CONN;
  }

  err_t err = ERR_OK;
  if (local) {
    ip_addr_copy(*addr,
        conn->pcb.ip->local_ip);
  } else {
    ip_addr_copy(*addr,
        conn->pcb.ip->remote_ip);
  }

  switch (NETCONNTYPE_GROUP(conn->type)) {
    case NETCONN_RAW:
      if (local) {
        *port = conn->pcb.raw->protocol;
      } else {
        err = ERR_CONN;
      }
      break;
    case NETCONN_UDP:
      if (local) {
        rakis_rwlock_read_lock(&conn->pcb.udp->pcb_lock);
        *port = conn->pcb.udp->local_port;
        rakis_rwlock_read_unlock(&conn->pcb.udp->pcb_lock);
      } else {
        if ((RAKIS_GET_ATOMIC(&(conn->pcb.udp->flags_atm)) & UDP_FLAGS_CONNECTED) == 0) {
          err = ERR_CONN;
        } else {
        rakis_rwlock_read_lock(&conn->pcb.udp->pcb_lock);
          *port = conn->pcb.udp->remote_port;
        rakis_rwlock_read_unlock(&conn->pcb.udp->pcb_lock);
        }
      }
      break;
    default:
      LWIP_ASSERT("invalid netconn_type", 0);
      break;
  }

  return err;
}

static int lwip_getaddrname(int s, struct sockaddr *name, socklen_t *namelen, u8_t local){
  struct lwip_sock *sock;
  union sockaddr_aligned saddr;
  ip_addr_t naddr;
  u16_t port;
  err_t err;

  sock = get_socket(s);
  if (!sock) {
    return -1;
  }

  err = netconn_getaddr(sock->conn, &naddr, &port, local);
  if (err != ERR_OK) {
    sock_set_errno(err_to_errno(err));
    done_socket(sock);
    return -1;
  }

  IPADDR_PORT_TO_SOCKADDR(&saddr, &naddr, port);

  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getaddrname(%d, addr=", s));
  ip_addr_debug_print_val(SOCKETS_DEBUG, naddr);
  LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%"U16_F")\n", port));

  if (*namelen > sizeof(saddr.sa)) {
    *namelen = sizeof(saddr.sa);
  }
  MEMCPY(name, &saddr, *namelen);

  sock_set_errno(0);
  done_socket(sock);
  return 0;
}

int lwip_getpeername(int s, struct sockaddr *name, socklen_t *namelen){
  return lwip_getaddrname(s, name, namelen, 0);
}

int lwip_getsockname(int s, struct sockaddr *name, socklen_t *namelen){
  return lwip_getaddrname(s, name, namelen, 1);
}

static err_t netconn_send(struct netconn *conn, struct pbuf* p){
  err_t err = ERR_OK;

  if (conn->pcb.ip != NULL) {
    switch (NETCONNTYPE_GROUP(conn->type)) {
      case NETCONN_RAW:
        if (ip_addr_isany(&p->net_ip_addr)) {
          err = raw_send(conn->pcb.raw, p);
        } else {
          err = raw_sendto(conn->pcb.raw, p, &p->net_ip_addr);
        }
        break;

      case NETCONN_UDP:
        if (ip_addr_isany_val(p->net_ip_addr)) {
          err = udp_sendto(conn->pcb.udp, p, NULL, 0);
        } else {
          err = udp_sendto(conn->pcb.udp, p, &p->net_ip_addr, p->net_port);
        }
        break;

      default:
        err = ERR_CONN;
        break;
    }

  } else {
    err = ERR_CONN;
  }
  return err;
}

ssize_t lwip_send(int s, const void *data, size_t size, int flags){
  return lwip_sendto(s, data, size, flags, NULL, 0);
}

ssize_t lwip_sendmsg(int s, const struct msghdr *msg, int flags) {
  RAKIS_STAT_DURATION_START(send_duration);
  RAKIS_STAT_INC(send_count);

  struct lwip_sock *sock;
  err_t err = ERR_OK;
  ssize_t size = 0;
  LWIP_UNUSED_ARG(flags);

  sock = get_socket(s);
  if (!sock) {
    return -1;
  }

  LWIP_ERROR("lwip_sendmsg: invalid msghdr", msg != NULL,
             sock_set_errno(err_to_errno(ERR_ARG)); done_socket(sock); return -1;);
  LWIP_ERROR("lwip_sendmsg: invalid msghdr iov", msg->msg_iov != NULL,
             sock_set_errno(err_to_errno(ERR_ARG)); done_socket(sock); return -1;);
  LWIP_ERROR("lwip_sendmsg: maximum iovs exceeded", (msg->msg_iovlen > 0) && (msg->msg_iovlen <= IOV_MAX),
             sock_set_errno(EMSGSIZE); done_socket(sock); return -1;);
  LWIP_ERROR("lwip_sendmsg: unsupported flags", (flags & ~(MSG_DONTWAIT | MSG_MORE)) == 0,
             sock_set_errno(EOPNOTSUPP); done_socket(sock); return -1;);
  LWIP_ERROR("lwip_sendmsg: invalid msghdr name", (((msg->msg_name == NULL) && (msg->msg_namelen == 0)) ||
        IS_SOCK_ADDR_LEN_VALID(msg->msg_namelen)),
      sock_set_errno(err_to_errno(ERR_ARG)); done_socket(sock); return -1;);

  struct pbuf* head_p = NULL;
  for (u32 i = 0; i < msg->msg_iovlen; i++) {
    struct pbuf *p;
    if (msg->msg_iov[i].iov_len > 0xFFFF) {
      /* overflow */
      goto sendmsg_emsgsize;
    }
    p = pbuf_alloc_ref();
    if (p == NULL) {
      err = ERR_MEM; /* let netbuf_delete() cleanup chain_buf */
      break;
    }
    p->payload = msg->msg_iov[i].iov_base;
    p->len = p->tot_len = (u16_t)msg->msg_iov[i].iov_len;
    /* netbuf empty, add new pbuf */
    if (head_p == NULL) {
      head_p = p;
      /* add pbuf to existing pbuf chain */
    } else {
      if (head_p->tot_len + p->len > 0xffff) {
        /* overflow */
        pbuf_free(p);
        goto sendmsg_emsgsize;
      }
      pbuf_cat(head_p, p);
    }
  }

  if (msg->msg_name) {
    u16_t remote_port;
    SOCKADDR_TO_IPADDR_PORT((const struct sockaddr *)msg->msg_name, &head_p->net_ip_addr, remote_port);
    head_p->net_port = remote_port;
  }

  /* save size of total chain */
  if (err == ERR_OK) {
    size = head_p->tot_len;
  }

  if (err == ERR_OK) {
    /* send the data */
    err = netconn_send(sock->conn, head_p);
  }

  pbuf_free(head_p);
  sock_set_errno(err_to_errno(err));
  done_socket(sock);
  RAKIS_STAT_DURATION_END(send_duration);
  return (err == ERR_OK ? size : -1);

sendmsg_emsgsize:
  sock_set_errno(EMSGSIZE);
  pbuf_free(head_p);
  done_socket(sock);
  return -1;
}

ssize_t lwip_sendto(int s, const void *data, size_t size, int flags, const struct sockaddr *to, socklen_t tolen) {
  RAKIS_STAT_INC(send_count);
  LWIP_UNUSED_ARG(flags);

  struct lwip_sock *sock;
  err_t err;
  u16_t short_size;
  u16_t remote_port;
  struct pbuf* send_buf;

  sock = get_socket(s);
  if (!sock) {
    return -1;
  }

  if (size > LWIP_MIN(0xFFFF, SSIZE_MAX)) {
    /* cannot fit into one datagram (at least for us) */
    sock_set_errno(EMSGSIZE);
    done_socket(sock);
    return -1;
  }

  short_size = (u16_t)size;
  LWIP_ERROR("lwip_sendto: invalid address", (((to == NULL) && (tolen == 0)) ||
             (IS_SOCK_ADDR_LEN_VALID(tolen) &&
              ((to != NULL) && (IS_SOCK_ADDR_TYPE_VALID(to) && IS_SOCK_ADDR_ALIGNED(to))))),
             sock_set_errno(err_to_errno(ERR_ARG)); done_socket(sock); return -1;);
  LWIP_UNUSED_ARG(tolen);

  /* make the buffer point to the data that should be sent */
  send_buf = pbuf_alloc_ref();
  if (send_buf == NULL) {
    err = ERR_MEM;
    goto out;
  }

  if (to) {
    SOCKADDR_TO_IPADDR_PORT(to, &send_buf->net_ip_addr, remote_port);
  } else {
    remote_port = 0;
    ip_addr_set_any(NETCONNTYPE_ISIPV6(netconn_type(sock->conn)), &send_buf->net_ip_addr);
  }
  send_buf->net_port = remote_port;


  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_sendto(%d, data=%p, short_size=%"U16_F", flags=0x%x to=",
                              s, data, short_size, flags));
  ip_addr_debug_print_val(SOCKETS_DEBUG, send_buf->net_ip_addr);
  LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%"U16_F"\n", remote_port));

  send_buf->payload = (void*)data;
  send_buf->len = send_buf->tot_len = size;
  err = netconn_send(sock->conn, send_buf);
  pbuf_free(send_buf);

out:
  sock_set_errno(err_to_errno(err));
  done_socket(sock);
  return (err == ERR_OK ? short_size : -1);
}

ssize_t lwip_write(int s, const void *data, size_t size) {
  return lwip_send(s, data, size, 0);
}

ssize_t lwip_writev(int s, const struct iovec *iov, int iovcnt) {
  struct msghdr msg;

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  /* Hack: we have to cast via number to cast from 'const' pointer to non-const.
     Blame the opengroup standard for this inconsistency. */
  msg.msg_iov = LWIP_CONST_CAST(struct iovec *, iov);
  msg.msg_iovlen = iovcnt;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  return lwip_sendmsg(s, &msg, 0);
}

static int lwip_sock_make_addr(struct netconn *conn, ip_addr_t *fromaddr, u16_t port, struct sockaddr *from, int *fromlen_s) {
  int truncated = 0;
  union sockaddr_aligned saddr;
  socklen_t *fromlen = (socklen_t *)fromlen_s;
  LWIP_UNUSED_ARG(conn);

  LWIP_ASSERT("fromaddr != NULL", fromaddr != NULL);
  LWIP_ASSERT("from != NULL", from != NULL);
  LWIP_ASSERT("fromlen != NULL", fromlen != NULL);

  IPADDR_PORT_TO_SOCKADDR(&saddr, fromaddr, port);
  if (*fromlen < sizeof(saddr.sa)) {
    truncated = 1;
  } else if (*fromlen > sizeof(saddr.sa)) {
    *fromlen = sizeof(saddr.sa);
  }
  MEMCPY(from, &saddr, *fromlen);
  return truncated;
}

static err_t recvfrom_udp_raw_peek(struct lwip_sock *sock, int apiflags, struct msghdr *msg, u16_t *datagram_len){
  struct netconn *conn = sock->conn;
  struct pktq* recvq = conn->recvq;
  struct pbuf* recv_buf;
  u16_t buflen, copylen, copied;
  err_t erro = ERR_OK;

  RAKIS_SLOCK(&recvq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
  if (pktq_can_dequeue_cons_locked(recvq) == 0){
    if (netconn_is_nonblocking(conn) || (apiflags & NETCONN_DONTBLOCK)) {
      erro = ERR_WOULDBLOCK;
      goto out;

    } else {
      u64_t timeout = netconn_get_recvtimeout(conn);
      u64_t* timeout_ptr = timeout == 0 ? NULL : &timeout;

      while (pktq_can_dequeue_cons_locked(recvq) == 0) {

#ifndef RAKIS_BUSYLOOP_RECV
        int event_ret = rakis_event_wait(conn->recvevent, timeout_ptr);
        if (event_ret < 0){
          if (event_ret == RAKIS_EVENT_TIMEOUT) {
            err = ERR_TIMEOUT;
          }else{
            err = ERR_ABRT;
          }

          goto out;
        }
#else
        if (timeout_ptr != NULL && timeout-- == 0) {
          erro = ERR_TIMEOUT;
          goto out;
        }
#endif

        if (RAKIS_GET_ATOMIC(&conn->flags_atm)
            & NETCONN_FLAG_MBOXINVALID) {

          erro = ERR_CONN;
          goto out;
        }
      }
    }
  }

  recv_buf = pktq_dequeue_peek_cons_locked(recvq);
  buflen = recv_buf->tot_len;
  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom_udp_raw: buflen=%"U16_F"\n", buflen));

  copied = 0;
  /* copy the pbuf payload into the iovs */
  for (u32 i = 0; (i < msg->msg_iovlen) && (copied < buflen); i++) {
    u16_t len_left = (u16_t)(buflen - copied);
    if (msg->msg_iov[i].iov_len > len_left) {
      copylen = len_left;
    } else {
      copylen = (u16_t)msg->msg_iov[i].iov_len;
    }

    /* copy the contents of the received buffer into
        the supplied memory buffer */
    pbuf_copy_partial(recv_buf, (u8_t *)msg->msg_iov[i].iov_base, copylen, copied);
    copied = (u16_t)(copied + copylen);
  }

  /* Check to see from where the data was.*/
  if (msg->msg_name && msg->msg_namelen){
    LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom_udp_raw:  addr="));
    ip_addr_debug_print_val(SOCKETS_DEBUG, recv_buf->net_ip_addr);
    LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%"U16_F" len=%d\n", recv_buf->net_port, copied));
    if (msg->msg_name && msg->msg_namelen) {
      lwip_sock_make_addr(sock->conn, &recv_buf->net_ip_addr, recv_buf->net_port,
                          (struct sockaddr *)msg->msg_name, &msg->msg_namelen);
    }
  }

  msg->msg_flags = 0;
  if (msg->msg_control) {
    msg->msg_controllen = 0;
  }

  if (datagram_len) {
    *datagram_len = buflen;
  }

out:
  RAKIS_SUNLOCK(&recvq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
  return erro;
}

static err_t recvfrom_udp_raw_dequeue(struct lwip_sock *sock, u8_t apiflags, struct msghdr *msg, u16_t *datagram_len){
  struct netconn *conn = sock->conn;
  struct pktq* recvq = conn->recvq;
  struct pbuf* recv_buf;
  u16_t buflen, copylen, copied;

  RAKIS_SLOCK(&recvq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
  if (pktq_can_dequeue_cons_locked(recvq) == 0){
    if (netconn_is_nonblocking(conn) || (apiflags & NETCONN_DONTBLOCK)) {
      RAKIS_SUNLOCK(&recvq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
      return ERR_WOULDBLOCK;

    } else {
      u64_t timeout = netconn_get_recvtimeout(conn);
      u64_t* timeout_ptr = timeout == 0 ? NULL : &timeout;

      while (pktq_can_dequeue_cons_locked(recvq) == 0) {

#ifndef RAKIS_BUSYLOOP_RECV
        int event_ret = rakis_event_wait(conn->recvevent, timeout_ptr);
        if (event_ret < 0){
          if (event_ret == RAKIS_EVENT_TIMEOUT) {
            RAKIS_SUNLOCK(&recvq->cons_lock);
            return ERR_TIMEOUT;

          }else{

            RAKIS_SUNLOCK(&recvq->cons_lock);
            return ERR_ABRT;
          }
        }
#else
        if (timeout_ptr != NULL && timeout-- == 0) {
          RAKIS_SUNLOCK(&recvq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
          return ERR_TIMEOUT;
        }
#endif

        if (RAKIS_GET_ATOMIC(&conn->flags_atm)
            & NETCONN_FLAG_MBOXINVALID) {

          RAKIS_SUNLOCK(&recvq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
          return ERR_CONN;
        }
      }
    }
  }

  recv_buf = pktq_dequeue_commit_cons_locked(recvq);
  pktq_dequeue_push_cons_locked(recvq);
  RAKIS_SUNLOCK(&recvq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));

  buflen = recv_buf->tot_len;
  RAKIS_SUB_ATOMIC(&conn->recv_avail_atm, buflen);

#ifndef RAKIS_BUSYLOOP_RECV
  // BUG: this is not thread safe
  // TODO: fix this
  rakis_event_reset(conn->recvevent);
#endif

  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom_udp_raw: buflen=%"U16_F"\n", buflen));

  copied = 0;
  /* copy the pbuf payload into the iovs */
  for (u32 i = 0; (i < msg->msg_iovlen) && (copied < buflen); i++) {
    u16_t len_left = (u16_t)(buflen - copied);
    if (msg->msg_iov[i].iov_len > len_left) {
      copylen = len_left;
    } else {
      copylen = (u16_t)msg->msg_iov[i].iov_len;
    }

    /* copy the contents of the received buffer into
        the supplied memory buffer */
    pbuf_copy_partial(recv_buf, (u8_t *)msg->msg_iov[i].iov_base, copylen, copied);
    copied = (u16_t)(copied + copylen);
  }

  /* Check to see from where the data was.*/
  if (msg->msg_name && msg->msg_namelen){
    LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom_udp_raw:  addr="));
    ip_addr_debug_print_val(SOCKETS_DEBUG, recv_buf->net_ip_addr);
    LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%"U16_F" len=%d\n", recv_buf->net_port, copied));
    if (msg->msg_name && msg->msg_namelen) {
      lwip_sock_make_addr(sock->conn, &recv_buf->net_ip_addr, recv_buf->net_port,
                          (struct sockaddr *)msg->msg_name, &msg->msg_namelen);
    }
  }
  pbuf_free(recv_buf);

  msg->msg_flags = 0;
  if (msg->msg_control) {
    msg->msg_controllen = 0;
  }

  if (datagram_len) {
    *datagram_len = buflen;
  }

  return ERR_OK;
}

static err_t recvfrom_udp_raw(struct lwip_sock *sock, int flags, struct msghdr *msg, u16_t *datagram_len, int dbg_s){
  struct netconn *conn = sock->conn;
  u8_t ispeek, apiflags;

  LWIP_UNUSED_ARG(dbg_s);
  LWIP_ERROR("lwip_recvfrom_udp_raw: invalid arguments", (msg->msg_iov != NULL) || (msg->msg_iovlen <= 0), return ERR_ARG;);

  if (RAKIS_GET_ATOMIC(&conn->flags_atm)
      & NETCONN_FLAG_MBOXINVALID) {
    return ERR_CONN;
  }

  ispeek = (flags & MSG_PEEK) != 0;
  apiflags = (flags & MSG_DONTWAIT) ? NETCONN_DONTBLOCK : 0;

  if (ispeek){
    return recvfrom_udp_raw_peek(sock, apiflags, msg, datagram_len);
  }else{
    return recvfrom_udp_raw_dequeue(sock, apiflags, msg, datagram_len);
  }
}

ssize_t lwip_recvfrom(int s, void *mem, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){
  RAKIS_STAT_DURATION_START(recv_duration);
  RAKIS_STAT_INC(recv_count);
  struct lwip_sock *sock;
  ssize_t ret;

  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom(%d, %p, %"SZT_F", 0x%x, ..)\n", s, mem, len, flags));
  sock = get_socket(s);
  if (!sock) {
    return -1;
  }

  u16_t datagram_len = 0;
  struct iovec vec;
  struct msghdr msg;
  err_t err;
  vec.iov_base = mem;
  vec.iov_len = len;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_name = from;
  msg.msg_namelen = (fromlen ? *fromlen : 0);
  err = recvfrom_udp_raw(sock, flags, &msg, &datagram_len, s);
  if (err != ERR_OK) {
    LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom[UDP/RAW](%d): buf == NULL, error is \"%s\"!\n",
          s, lwip_strerr(err)));
    sock_set_errno(err_to_errno(err));
    done_socket(sock);
    return -1;
  }

  ret = (ssize_t)LWIP_MIN(LWIP_MIN(len, datagram_len), SSIZE_MAX);
  if (fromlen) {
    *fromlen = msg.msg_namelen;
  }

  sock_set_errno(0);
  done_socket(sock);
  RAKIS_STAT_DURATION_END(recv_duration);
  return ret;
}

ssize_t
lwip_read(int s, void *mem, size_t len)
{
  return lwip_recvfrom(s, mem, len, 0, NULL, NULL);
}

ssize_t
lwip_readv(int s, const struct iovec *iov, int iovcnt)
{
  struct msghdr msg;

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  /* Hack: we have to cast via number to cast from 'const' pointer to non-const.
     Blame the opengroup standard for this inconsistency. */
  msg.msg_iov = LWIP_CONST_CAST(struct iovec *, iov);
  msg.msg_iovlen = iovcnt;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  return lwip_recvmsg(s, &msg, 0);
}

ssize_t
lwip_recv(int s, void *mem, size_t len, int flags)
{
  return lwip_recvfrom(s, mem, len, flags, NULL, NULL);
}

ssize_t
lwip_recvmsg(int s, struct msghdr *message, int flags) {
  struct lwip_sock *sock;
  ssize_t buflen;

  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvmsg(%d, message=%p, flags=0x%x)\n", s, (void *)message, flags));
  LWIP_ERROR("lwip_recvmsg: invalid message pointer", message != NULL, return ERR_ARG;);
  LWIP_ERROR("lwip_recvmsg: unsupported flags", (flags & ~(MSG_PEEK|MSG_DONTWAIT)) == 0,
             set_errno(EOPNOTSUPP); return -1;);

  if ((message->msg_iovlen <= 0) || (message->msg_iovlen > IOV_MAX)) {
    set_errno(EMSGSIZE);
    return -1;
  }

  sock = get_socket(s);
  if (!sock) {
    return -1;
  }

  /* check for valid vectors */
  buflen = 0;
  for (u32 i = 0; i < message->msg_iovlen; i++) {
    if ((message->msg_iov[i].iov_base == NULL) || ((ssize_t)message->msg_iov[i].iov_len <= 0) ||
        ((size_t)(ssize_t)message->msg_iov[i].iov_len != message->msg_iov[i].iov_len) ||
        ((ssize_t)(buflen + (ssize_t)message->msg_iov[i].iov_len) <= 0)) {
      sock_set_errno(err_to_errno(ERR_VAL));
      done_socket(sock);
      return -1;
    }
    buflen = (ssize_t)(buflen + (ssize_t)message->msg_iov[i].iov_len);
  }

  if (NETCONNTYPE_GROUP(netconn_type(sock->conn)) == NETCONN_INVALID) {
    sock_set_errno(err_to_errno(ERR_ARG));
    done_socket(sock);
    return -1;
  }

  u16_t datagram_len = 0;
  err_t err;
  err = recvfrom_udp_raw(sock, flags, message, &datagram_len, s);
  if (err != ERR_OK) {
    LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvmsg[UDP/RAW](%d): buf == NULL, error is \"%s\"!\n",
          s, lwip_strerr(err)));
    sock_set_errno(err_to_errno(err));
    done_socket(sock);
    return -1;
  }

  if (datagram_len > buflen) {
    message->msg_flags |= MSG_TRUNC;
  }

  sock_set_errno(0);
  done_socket(sock);
  return (int)datagram_len;
}

static void
lwip_poll_inc_sockets_used(struct pollfd *fds, nfds_t nfds)
{
  nfds_t fdi;

  if(fds) {
    /* Go through each struct pollfd in the array. */
    for (fdi = 0; fdi < nfds; fdi++) {
      /* Increase the reference counter */
      tryget_socket_unconn(fds[fdi].fd);
    }
  }
}

static void
lwip_poll_dec_sockets_used(struct pollfd *fds, nfds_t nfds)
{
  nfds_t fdi;

  if(fds) {
    /* Go through each struct pollfd in the array. */
    for (fdi = 0; fdi < nfds; fdi++) {
      struct lwip_sock *sock = tryget_socket_unconn_nouse(fds[fdi].fd);
      if (sock != NULL) {
        done_socket(sock);
      }
    }
  }
}

static int
lwip_pollscan(struct pollfd *fds, nfds_t nfds, bool clear)
{
  int nready = 0;
  nfds_t fdi;
  struct lwip_sock *sock;

  /* Go through each struct pollfd in the array. */
  for (fdi = 0; fdi < nfds; fdi++) {
    if (clear) {
      fds[fdi].revents = 0;
    }

    /* Negative fd means the caller wants us to ignore this struct.
       POLLNVAL means we already detected that the fd is invalid;
       if another thread has since opened a new socket with that fd,
       we must not use that socket. */
    if (fds[fdi].fd >= 0 && (fds[fdi].revents & POLLNVAL) == 0) {
      /* First get the socket's status (protected)... */
      sock = tryget_socket(fds[fdi].fd);
      if (sock != NULL) {
        struct netconn* conn = sock->conn;
        struct pktq* recvq = conn->recvq;
        RAKIS_SLOCK(&recvq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
        u32_t rcvevent = pktq_can_dequeue_cons_locked(recvq);
        RAKIS_SUNLOCK(&recvq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
        done_socket(sock);

        LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_pollscan: Now examining %d\n", fds[fdi].fd));
        if ((fds[fdi].events & POLLIN) != 0 && ((rcvevent > 0))) {
          fds[fdi].revents |= POLLIN;
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_pollscan: fd=%d ready for reading\n", fds[fdi].fd));
        }
        if ((fds[fdi].events & POLLOUT) != 0) {
          fds[fdi].revents |= POLLOUT;
          LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_pollscan: fd=%d ready for writing\n", fds[fdi].fd));
        }
      } else {
        /* Not a valid socket */
        /* POLLNVAL is output only. */
        fds[fdi].revents |= POLLNVAL;
      }
    }

    /* Will return the number of structures that have events,
       not the number of events. */
    if (fds[fdi].revents != 0) {
      nready++;
    }
  }

  LWIP_ASSERT("nready >= 0", nready >= 0);
  return nready;
}

static void add_poll_cb(struct rakis_poll_cb *poll_cb) {
  RAKIS_SLOCK(&poll_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_poll_cb_lock));
  poll_cb->next = poll_cb_list;
  if (poll_cb_list != NULL) {
    poll_cb_list->prev = poll_cb;
  }
  poll_cb_list = poll_cb;
  RAKIS_SUNLOCK(&poll_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_poll_cb_lock));
}

/* Remove select_cb from select_cb_list. */
static void remove_poll_cb(struct rakis_poll_cb *poll_cb) {
  RAKIS_SLOCK(&poll_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_poll_cb_lock));

  if (poll_cb->next != NULL) {
    poll_cb->next->prev = poll_cb->prev;
  }
  if (poll_cb_list == poll_cb) {
    LWIP_ASSERT("select_cb->prev == NULL", poll_cb->prev == NULL);
    poll_cb_list = poll_cb->next;
  } else {
    LWIP_ASSERT("select_cb->prev != NULL", poll_cb->prev != NULL);
    poll_cb->prev->next = poll_cb->next;
  }

  RAKIS_SUNLOCK(&poll_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_poll_cb_lock));
}

int
lwip_poll_start(struct pollfd *fds, nfds_t nfds, struct rakis_poll_cb* poll_cb){
  int nready;

  // increase use of the sockets we are polling on
  lwip_poll_inc_sockets_used(fds, nfds);

  // do we have anything ready to return?
  nready = lwip_pollscan(fds, nfds, true);
  if (nready > 0){
    lwip_poll_dec_sockets_used(fds, nfds);
    set_errno(0);
    return nready;
  }

  // nothing is ready, we register it so that the main thread can wake us up
  // by writing to the socket pipe
  poll_cb->poll_fds = fds;
  poll_cb->poll_nfds = nfds;
  RAKIS_SET_ATOMIC(&poll_cb->notify_mem, false);

  // add us to the select list
  add_poll_cb(poll_cb);

  /* Increase select_waiting for each socket we are interested in.
     Also, check for events again: there could have been events between
     the last scan (without us on the list) and putting us on the list! */
  nready = lwip_pollscan(fds, nfds, 0);
  if (nready > 0) {
    lwip_pollscan(fds, nfds, false);
    remove_poll_cb(poll_cb);
    lwip_poll_dec_sockets_used(fds, nfds);
    set_errno(0);
    return nready;
  }

  // otherwise, we return, letting the caller know that we have not gotten anything
  return 0;
}

int lwip_poll_end(struct pollfd *fds, nfds_t nfds, struct rakis_poll_cb* poll_cb){
  int nready;

  /* Decrease select_waiting for each socket we are interested in,
     and check which events occurred while we waited. */
  nready = lwip_pollscan(fds, nfds, false);

  // decrement use of the sockets and unlink from the select list
  remove_poll_cb(poll_cb);
  lwip_poll_dec_sockets_used(fds, nfds);

  LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_poll_end: nready=%d\n", nready));
  set_errno(0);
  return nready;
}
