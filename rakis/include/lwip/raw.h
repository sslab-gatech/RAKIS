/**
 * @file
 * raw API (to be used from TCPIP thread)\n
 * See also @ref raw_raw
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
#ifndef LWIP_HDR_RAW_H
#define LWIP_HDR_RAW_H

#include "lwip/opt.h"

#include "lwip/pbuf.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"
#include "rakis/stack/rakis_rwlock.h"

#define RAW_FLAGS_CONNECTED      0x01U
#define RAW_FLAGS_HDRINCL        0x02U

/** return codes for raw_input */
typedef enum raw_input_state
{
  RAW_INPUT_NONE = 0, /* pbuf did not match any pcbs */
  RAW_INPUT_EATEN,    /* pbuf handed off and delivered to pcb */
  RAW_INPUT_DELIVERED /* pbuf only delivered to pcb (pbuf can still be referenced) */
} raw_input_state_t;

raw_input_state_t raw_input(struct ip_current* ip_data, struct pbuf *p, struct netif *inp);

struct raw_pcb;

/** Function prototype for raw pcb receive callback functions.
 * @param arg user supplied argument (raw_pcb.recv_arg)
 * @param pcb the raw_pcb which received data
 * @param p the packet buffer that was received
 * @param addr the remote IP address from which the packet was received
 * @return 1 if the packet was 'eaten' (aka. deleted),
 *         0 if the packet lives on
 * If returning 1, the callback is responsible for freeing the pbuf
 * if it's not used any more.
 */
typedef u8_t (*raw_recv_fn)(void *arg, struct raw_pcb *pcb, struct pbuf *p,
    const ip_addr_t *addr);

/** the RAW protocol control block */
struct raw_pcb {
  /* Common members of all PCB types */
  IP_PCB;

  struct raw_pcb *next;

  u8_t protocol;
  u8_t flags;

  /** receive callback function */
  raw_recv_fn recv;
  /* user-supplied argument for the recv callback */
  void *recv_arg;

  struct rakis_rwlock pcb_lock;
};

/* The following functions is the application layer interface to the
   RAW code. */
struct raw_pcb * raw_new        (u8_t proto);
struct raw_pcb * raw_new_ip_type(u8_t type, u8_t proto);
void             raw_remove     (struct raw_pcb *pcb);
err_t            raw_bind       (struct raw_pcb *pcb, const ip_addr_t *ipaddr);
void             raw_bind_netif (struct raw_pcb *pcb, const struct netif *netif);
err_t            raw_connect    (struct raw_pcb *pcb, const ip_addr_t *ipaddr);
void             raw_disconnect (struct raw_pcb *pcb);

err_t            raw_sendto     (struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *ipaddr);
err_t            raw_send       (struct raw_pcb *pcb, struct pbuf *p);

void             raw_set_recv_callback       (struct raw_pcb *pcb, raw_recv_fn recv, void *recv_arg);
int              raw_init       (void);

#define          raw_flags(pcb) ((pcb)->flags)
#define          raw_setflags(pcb,f)  ((pcb)->flags = (f))

#define          raw_set_flags(pcb, set_flags)     do { (pcb)->flags = (u8_t)((pcb)->flags |  (set_flags)); } while(0)
#define          raw_clear_flags(pcb, clr_flags)   do { (pcb)->flags = (u8_t)((pcb)->flags & (u8_t)(~(clr_flags) & 0xff)); } while(0)
#define          raw_is_flag_set(pcb, flag)        (((pcb)->flags & (flag)) != 0)

#endif /* LWIP_HDR_RAW_H */
