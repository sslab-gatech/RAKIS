/**
 * @file
 * netconn API (to be used from non-TCPIP threads)
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
 */
#ifndef LWIP_HDR_API_H
#define LWIP_HDR_API_H

#include "lwip/opt.h"

#include "lwip/arch.h"
#include "lwip/ip_addr.h"
#include "lwip/err.h"
#include "rakis/stack/rakis_spinlock.h"
#include "rakis/stack/rakis_event.h"

/* Throughout this file, IP addresses and port numbers are expected to be in
 * the same byte order as in the corresponding pcb.
 */

/* Flags for netconn_write (u8_t) */
#define NETCONN_NOFLAG      0x00
#define NETCONN_DONTBLOCK   0x04

/* Flags for struct netconn.flags (u8_t) */
/** Should this netconn avoid blocking? */
#define NETCONN_FLAG_NON_BLOCKING             0x02
  /** The mbox of this netconn is being deallocated, don't use it anymore */
#define NETCONN_FLAG_MBOXINVALID              0x08

/* Helpers to process several netconn_types by the same code */
#define NETCONNTYPE_GROUP(t)         ((t)&0xF0)
#define NETCONNTYPE_DATAGRAM(t)      ((t)&0xE0)
#define NETCONNTYPE_ISIPV6(t)        (0)
#define NETCONNTYPE_ISUDPLITE(t)     ((t) == NETCONN_UDPLITE)
#define NETCONNTYPE_ISUDPNOCHKSUM(t) ((t) == NETCONN_UDPNOCHKSUM)

/** @ingroup netconn_common
 * Protocol family and type of the netconn
 */
enum netconn_type {
  NETCONN_INVALID     = 0,
  /** UDP IPv4 */
  NETCONN_UDP         = 0x20,
  /** Raw connection IPv4 */
  NETCONN_RAW         = 0x40
};

/* forward-declare some structs to avoid to include their headers */
struct ip_pcb;
struct udp_pcb;
struct raw_pcb;
struct netconn;
struct api_msg;

/** A callback prototype to inform about events for a netconn */
typedef void (* netconn_callback)(struct netconn *);

/** A netconn descriptor */
struct netconn {
  /** type of the netconn (TCP, UDP or RAW) */
  enum netconn_type type;
  /** the lwIP internal protocol control block */
  union {
    struct ip_pcb  *ip;
    struct udp_pcb *udp;
    struct raw_pcb *raw;
  } pcb;
  /** mbox where received packets are stored until they are fetched
      by the netconn application thread (can grow quite big) */
  struct pktq* recvq;
  struct rakis_event* recvevent;
  /** only used for socket layer */
  int socket;
  /** timeout to wait for sending data (which means enqueueing data for sending
      in internal buffers) in milliseconds */
  u64_t send_timeout_atm;
  /** timeout in milliseconds to wait for new data to be received
      (or connections to arrive for listening netconns) */
  u64_t recv_timeout_atm;
  /** maximum amount of bytes queued in recvmbox
      not used for TCP: adjust TCP_WND instead! */
  int recv_bufsize_atm;
  /** number of bytes currently in recvmbox to be received,
      tested against recv_bufsize to limit bytes on recvmbox
      for UDP and RAW, used for FIONREAD */
  int recv_avail_atm;
   /** values <0 mean linger is disabled, values > 0 are seconds to linger */
  s16_t linger_atm;
  /** flags holding more netconn-internal state, see NETCONN_FLAG_* defines */
  u8_t flags_atm;
  /** A callback function that is informed about events for this netconn */
  netconn_callback callback;
};

#define API_RECV_EVENT(c) if (c->callback) {         \
                           (*c->callback)(c); \
                         }

/* Network connection functions: */

/** @ingroup netconn_common
 * Create new netconn connection
 * @param t @ref netconn_type */
/** Get the type of a netconn (as enum netconn_type). */
#define netconn_type(conn) (conn->type)

#define netconn_set_flags(conn, set_flags)     do { RAKIS_OR_ATOMIC(&(conn->flags_atm), set_flags); } while(0)
#define netconn_clear_flags(conn, clr_flags)   do { RAKIS_AND_ATOMIC(&(conn->flags_atm), (~(clr_flags) & 0xff)); } while(0)
#define netconn_is_flag_set(conn, flag)        ((RAKIS_GET_ATOMIC(&(conn->flags_atm)) & (flag)) != 0)

/** Set the blocking status of netconn calls (@todo: write/send is missing) */
#define netconn_set_nonblocking(conn, val)  do { if(val) { \
  netconn_set_flags(conn, NETCONN_FLAG_NON_BLOCKING); \
} else { \
  netconn_clear_flags(conn, NETCONN_FLAG_NON_BLOCKING); }} while(0)
/** Get the blocking status of netconn calls (@todo: write/send is missing) */
#define netconn_is_nonblocking(conn)        ((RAKIS_GET_ATOMIC(&(conn->flags_atm)) & NETCONN_FLAG_NON_BLOCKING) != 0)


/** Set the send timeout in milliseconds */
#define netconn_set_sendtimeout(conn, timeout)      (RAKIS_SET_ATOMIC(&((conn)->send_timeout_atm), (timeout)))
/** Get the send timeout in milliseconds */
#define netconn_get_sendtimeout(conn)               (RAKIS_GET_ATOMIC(&((conn)->send_timeout_atm)))
/** Set the receive timeout in milliseconds */
#define netconn_set_recvtimeout(conn, timeout)      (RAKIS_SET_ATOMIC(&((conn)->recv_timeout_atm), (timeout)))
/** Get the receive timeout in milliseconds */
#define netconn_get_recvtimeout(conn)               (RAKIS_GET_ATOMIC(&((conn)->recv_timeout_atm)))
/** Set the receive buffer in bytes */
#define netconn_set_recvbufsize(conn, recvbufsize)  (RAKIS_SET_ATOMIC(&((conn)->recv_bufsize_atm), (recvbufsize)))
/** Get the receive buffer in bytes */
#define netconn_get_recvbufsize(conn)               (RAKIS_GET_ATOMIC(&((conn)->recv_bufsize_atm)))

#endif /* LWIP_HDR_API_H */
