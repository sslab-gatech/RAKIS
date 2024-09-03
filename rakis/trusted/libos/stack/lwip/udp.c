/**
 * @file
 * User Datagram Protocol module\n
 * The code for the User Datagram Protocol UDP & UDPLite (RFC 3828).\n
 * See also @ref udp_raw
 *
 * @defgroup udp_raw UDP
 * @ingroup callbackstyle_api
 * User Datagram Protocol module\n
 * @see @ref api
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

/* @todo Check the use of '(struct udp_pcb).chksum_len_rx'!
 */

#include "lwip/opt.h"

#if LWIP_UDP /* don't build if not configured for use in lwipopts.h */

#include "lwip/udp.h"
#include "lwip/def.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/mem.h"
#include "rakis/atomics.h"

#include <string.h>

#include "rakis/stack/rakis_rwlock.h"

#ifndef UDP_LOCAL_PORT_RANGE_START
/* From http://www.iana.org/assignments/port-numbers:
   "The Dynamic and/or Private Ports are those from 49152 through 65535" */
#define UDP_LOCAL_PORT_RANGE_START  0xe000
#define UDP_LOCAL_PORT_RANGE_END    0xffff
#define UDP_ENSURE_LOCAL_PORT_RANGE(port) ((u16_t)(((port) & (u16_t)~UDP_LOCAL_PORT_RANGE_START) + UDP_LOCAL_PORT_RANGE_START))
#endif

/* last local UDP port */
static u16_t udp_port = UDP_LOCAL_PORT_RANGE_START;

/* The list of UDP PCBs */
/* exported in udp.h (was static) */
static struct rakis_rwlock udp_pcbs_lock;
static struct udp_pcb *udp_pcbs;


/**
 * Initialize this module.
 */
int
udp_init(void)
{
  int ret;

  ret = rakis_rwlock_create(&udp_pcbs_lock);
  if(ret < 0){
    return -1;
  }

  udp_port = UDP_ENSURE_LOCAL_PORT_RANGE(UDP_LOCAL_PORT_RANGE_START);
  return 0;
}

/**
 * Allocate a new local UDP port.
 *
 * @return a new (free) local UDP port number
 */
static inline u16_t
udp_new_port(struct udp_pcb *locked_pcb)
{
  // udp_pcbs should be already locked before calling this function
  // also locked_pcb should be locked before calling this function
  u16_t n = 0;
  struct udp_pcb *pcb;

again:
  if (udp_port++ == UDP_LOCAL_PORT_RANGE_END) {
    udp_port = UDP_LOCAL_PORT_RANGE_START;
  }
  /* Check all PCBs. */
  for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
    if (pcb == locked_pcb) {
      continue;
    }
    rakis_rwlock_read_lock(&pcb->pcb_lock);
    u16_t pcb_port = pcb->local_port;
    rakis_rwlock_read_unlock(&pcb->pcb_lock);
    if (pcb_port == udp_port) {
      if (++n > (UDP_LOCAL_PORT_RANGE_END - UDP_LOCAL_PORT_RANGE_START)) {
        return 0;
      }
      goto again;
    }
  }
  return udp_port;
}

/** Common code to see if the current input packet matches the pcb
 * (current input packet is accessed via ip(4/6)_current_* macros)
 *
 * @param pcb pcb to check
 * @param inp network interface on which the datagram was received (only used for IPv4)
 * @param broadcast 1 if his is an IPv4 broadcast (global or subnet-only), 0 otherwise (only used for IPv4)
 * @return 1 on match, 0 otherwise
 */
static inline u8_t
udp_input_local_match(struct ip_current* ip_data, struct udp_pcb *pcb, struct netif *inp, u8_t broadcast)
{
  // pcb already locked before calling this function
  LWIP_UNUSED_ARG(inp);       /* in IPv6 only case */
  LWIP_UNUSED_ARG(broadcast); /* in IPv6 only case */

  LWIP_ASSERT("udp_input_local_match: invalid pcb", pcb != NULL);
  LWIP_ASSERT("udp_input_local_match: invalid netif", inp != NULL);

  /* check if PCB is bound to specific netif */
  if ((pcb->netif_idx != NETIF_NO_INDEX) &&
      (pcb->netif_idx != netif_get_index(ip_data->current_input_netif))) {
    return 0;
  }

  /* Special case: IPv4 broadcast: all or broadcasts in my subnet
   * Note: broadcast variable can only be 1 if it is an IPv4 broadcast */
  if (broadcast != 0) {
    {
      if (ip4_addr_isany(ip_2_ip4(&pcb->local_ip)) ||
          ((ip4_current_dest_addr()->addr == IPADDR_BROADCAST)) ||
          ip4_addr_netcmp(ip_2_ip4(&pcb->local_ip), ip4_current_dest_addr(), netif_ip4_netmask(inp))) {
        return 1;
      }
    }
  } else
    /* Handle IPv4 and IPv6: all or exact match */
    if (ip_addr_isany(&pcb->local_ip) || ip_addr_cmp(&pcb->local_ip, ip_current_dest_addr())) {
      return 1;
    }

  return 0;
}

/**
 * Process an incoming UDP datagram.
 *
 * Given an incoming UDP datagram (as a chain of pbufs) this function
 * finds a corresponding UDP PCB and hands over the pbuf to the pcbs
 * recv function. If no pcb is found or the datagram is incorrect, the
 * pbuf is freed.
 *
 * @param p pbuf to be demultiplexed to a UDP PCB (p->payload pointing to the UDP header)
 * @param inp network interface on which the datagram was received.
 *
 */
void
udp_input(struct ip_current* ip_data, struct pbuf *p, struct netif *inp)
{
  struct udp_hdr *udphdr;
  struct udp_pcb *pcb;
  struct udp_pcb *uncon_pcb;
  u16_t src, dest;
  u8_t broadcast;
  u8_t for_us = 0;

  LWIP_UNUSED_ARG(inp);

  LWIP_ASSERT("udp_input: invalid pbuf", p != NULL);
  LWIP_ASSERT("udp_input: invalid netif", inp != NULL);

  /* Check minimum length (UDP header) */
  if (p->len < UDP_HLEN) {
    /* drop short packets */
    LWIP_DEBUGF(UDP_DEBUG,
                ("udp_input: short UDP datagram (%"U16_F" bytes) discarded\n", p->tot_len));
    pbuf_free(p);
    return;
  }

  udphdr = (struct udp_hdr *)p->payload;

  /* is broadcast packet ? */
  broadcast = ip_addr_isbroadcast(ip_current_dest_addr(), ip_current_netif());

  LWIP_DEBUGF(UDP_DEBUG, ("udp_input: received datagram of length %"U16_F"\n", p->tot_len));

  /* convert src and dest ports to host byte order */
  src = lwip_ntohs(udphdr->src);
  dest = lwip_ntohs(udphdr->dest);

  udp_debug_print(udphdr);

  /* print the UDP source and destination */
  LWIP_DEBUGF(UDP_DEBUG, ("udp ("));
  ip_addr_debug_print_val(UDP_DEBUG, *ip_current_dest_addr());
  LWIP_DEBUGF(UDP_DEBUG, (", %"U16_F") <-- (", lwip_ntohs(udphdr->dest)));
  ip_addr_debug_print_val(UDP_DEBUG, *ip_current_src_addr());
  LWIP_DEBUGF(UDP_DEBUG, (", %"U16_F")\n", lwip_ntohs(udphdr->src)));

  pcb = NULL;
  uncon_pcb = NULL;
  /* Iterate through the UDP pcb list for a matching pcb.
   * 'Perfect match' pcbs (connected to the remote port & ip address) are
   * preferred. If no perfect match is found, the first unconnected pcb that
   * matches the local port and ip address gets the datagram. */
  rakis_rwlock_read_lock(&udp_pcbs_lock);
  for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
    rakis_rwlock_read_lock(&pcb->pcb_lock);
    /* print the PCB local and remote address */
    LWIP_DEBUGF(UDP_DEBUG, ("pcb ("));
    ip_addr_debug_print_val(UDP_DEBUG, pcb->local_ip);
    LWIP_DEBUGF(UDP_DEBUG, (", %"U16_F") <-- (", pcb->local_port));
    ip_addr_debug_print_val(UDP_DEBUG, pcb->remote_ip);
    LWIP_DEBUGF(UDP_DEBUG, (", %"U16_F")\n", pcb->remote_port));

    /* compare PCB local addr+port to UDP destination addr+port */
    if ((pcb->local_port == dest) &&
        (udp_input_local_match(ip_data, pcb, inp, broadcast) != 0)) {
      if ((RAKIS_GET_ATOMIC(&(pcb->flags_atm)) & UDP_FLAGS_CONNECTED) == 0) {
        if (uncon_pcb == NULL) {
          /* the first unconnected matching PCB */
          uncon_pcb = pcb;
        } else if (broadcast && ip4_current_dest_addr()->addr == IPADDR_BROADCAST) {
          /* global broadcast address (only valid for IPv4; match was checked before) */
          if (!IP_IS_V4_VAL(uncon_pcb->local_ip) || !ip4_addr_cmp(ip_2_ip4(&uncon_pcb->local_ip), netif_ip4_addr(inp))) {
            /* uncon_pcb does not match the input netif, check this pcb */
            if (IP_IS_V4_VAL(pcb->local_ip) && ip4_addr_cmp(ip_2_ip4(&pcb->local_ip), netif_ip4_addr(inp))) {
              /* better match */
              rakis_rwlock_read_unlock(&uncon_pcb->pcb_lock);
              uncon_pcb = pcb;
            }
          }
        } else if (!ip_addr_isany(&pcb->local_ip)) {
          /* prefer specific IPs over catch-all */
          rakis_rwlock_read_unlock(&uncon_pcb->pcb_lock);
          uncon_pcb = pcb;
        }
      }

      /* compare PCB remote addr+port to UDP source addr+port */
      if ((pcb->remote_port == src) &&
          (ip_addr_isany_val(pcb->remote_ip) ||
           ip_addr_cmp(&pcb->remote_ip, ip_current_src_addr()))) {
        /* the first fully matching PCB */
        break;
      }
    }

    if (pcb != uncon_pcb) {
      rakis_rwlock_read_unlock(&pcb->pcb_lock);
    }
  }
  rakis_rwlock_read_unlock(&udp_pcbs_lock);

  /* no fully matching pcb found? then look for an unconnected pcb */
  if (pcb == NULL) {
    pcb = uncon_pcb;
  }else{
    // no need to uncon_pcb anymore
    if (uncon_pcb != NULL) {
      rakis_rwlock_read_unlock(&uncon_pcb->pcb_lock);
    }
  }

  /* Check checksum if this is a match or if it was directed at us. */
  if (pcb != NULL) {
    for_us = 1;
  } else {
    if (!ip_current_is_v6()) {
      for_us = ip4_addr_cmp(netif_ip4_addr(inp), ip4_current_dest_addr());
    }
  }

  if (for_us) {
    if (pbuf_remove_header(p, UDP_HLEN)) {
      pbuf_free(p);
      goto end;
    }

    if (pcb != NULL) {
      /* callback */
      if (pcb->recv != NULL) {
        /* now the recv function is responsible for freeing p */
        pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr(), src);
      } else {
        /* no recv function registered? then we have to free the pbuf! */
        pbuf_free(p);
        goto end;
      }
    } else {
      LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_input: not for us.\n"));
      pbuf_free(p);
    }
  } else {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_input: not for us.\n"));
    pbuf_free(p);
  }
end:
  if (pcb != NULL) {
    rakis_rwlock_read_unlock(&pcb->pcb_lock);
  }
}

static inline err_t udp_bind_locked(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port){
  // called with udp_pcbs_lock and pcb->pcb_lock locked for write

  struct udp_pcb *ipcb;
  u8_t rebind;

  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_bind(ipaddr = "));
  ip_addr_debug_print(UDP_DEBUG | LWIP_DBG_TRACE, ipaddr);
  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, (", port = %"U16_F")\n", port));

  rebind = 0;
  /* Check for double bind and rebind of the same pcb */
  for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
    /* is this UDP PCB already on active list? */
    if (pcb == ipcb) {
      rebind = 1;
      break;
    }
  }

  /* no port specified? */
  if (port == 0) {
    port = udp_new_port(pcb);
    if (port == 0) {
      /* no more ports available in local range */
      LWIP_DEBUGF(UDP_DEBUG, ("udp_bind: out of free UDP ports\n"));
      return ERR_USE;
    }
  } else {
    for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
      if (pcb != ipcb) {
        /* By default, we don't allow to bind to a port that any other udp
           PCB is already bound to, unless *all* PCBs with that port have tha
           REUSEADDR flag set. */
        if (!ip_get_option(pcb, SOF_REUSEADDR) ||
            !ip_get_option(ipcb, SOF_REUSEADDR)){
          /* port matches that of PCB in list and REUSEADDR not set -> reject */
          if ((ipcb->local_port == port) &&
              (((IP_GET_TYPE(&ipcb->local_ip) == IP_GET_TYPE(ipaddr)) &&
              /* IP address matches or any IP used? */
              (ip_addr_cmp(&ipcb->local_ip, ipaddr) ||
              ip_addr_isany(ipaddr) ||
              ip_addr_isany(&ipcb->local_ip))) ||
              (IP_GET_TYPE(&ipcb->local_ip) == IPADDR_TYPE_ANY) ||
              (IP_GET_TYPE(ipaddr) == IPADDR_TYPE_ANY))) {
            /* other PCB already binds to this local IP and port */
            LWIP_DEBUGF(UDP_DEBUG,
                        ("udp_bind: local port %"U16_F" already bound by another pcb\n", port));
            return ERR_USE;
          }
        }
      }
    }
  }

  ip_addr_set_ipaddr(&pcb->local_ip, ipaddr);
  pcb->local_port = port;

  /* pcb not active yet? */
  if (rebind == 0) {
    /* place the PCB on the active list if not already there */
    pcb->next = udp_pcbs;
    udp_pcbs = pcb;
  }

  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("udp_bind: bound to "));
  ip_addr_debug_print_val(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, pcb->local_ip);
  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, (", port %"U16_F")\n", pcb->local_port));
  return ERR_OK;
}

/**
 * @ingroup udp_raw
 * Send data to a specified address using UDP.
 *
 * @param pcb UDP PCB used to send the data.
 * @param p chain of pbuf's to be sent.
 * @param dst_ip Destination IP address.
 * @param dst_port Destination UDP port.
 *
 * dst_ip & dst_port are expected to be in the same byte order as in the pcb.
 *
 * If the PCB already has a remote address association, it will
 * be restored after the data is sent.
 *
 * @return lwIP error code (@see udp_send for possible error codes)
 *
 * @see udp_disconnect() udp_send()
 */
err_t
udp_sendto(struct udp_pcb *pcb, struct pbuf *p,
           const ip_addr_t *dst_ip, u16_t dst_port){

  struct netif *netif;
  LWIP_ERROR("udp_send: invalid pcb", pcb != NULL, return ERR_ARG);
  LWIP_ERROR("udp_send: invalid pbuf", p != NULL, return ERR_ARG);

  rakis_rwlock_read_lock(&pcb->pcb_lock);

  if (dst_ip == NULL) {
    dst_ip = &pcb->remote_ip;
    dst_port = pcb->remote_port;
  }

  if (dst_ip == NULL) {
    rakis_rwlock_read_unlock(&pcb->pcb_lock);
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_sendto: invalid dst_ip\n"));
    return ERR_ARG;
  }

  if (!IP_ADDR_PCB_VERSION_MATCH(pcb, dst_ip)) {
    rakis_rwlock_read_unlock(&pcb->pcb_lock);
    return ERR_VAL;
  }

  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_send\n"));

  if (pcb->netif_idx != NETIF_NO_INDEX) {
    netif = netif_get_by_index(pcb->netif_idx);
  } else {
    /* find the outgoing network interface for this packet */
    netif = ip_route(&pcb->local_ip, dst_ip);
  }

  /* no outgoing network interface could be found? */
  if (netif == NULL) {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("udp_send: No route to "));
    ip_addr_debug_print(UDP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, dst_ip);
    LWIP_DEBUGF(UDP_DEBUG, ("\n"));
    rakis_rwlock_read_unlock(&pcb->pcb_lock);
    return ERR_RTE;
  }

  const ip_addr_t *src_ip;

  /* PCB local address is IP_ANY_ADDR or multicast? */
  if (ip4_addr_isany(ip_2_ip4(&pcb->local_ip)) ||
      ip4_addr_ismulticast(ip_2_ip4(&pcb->local_ip))) {
    /* if the local_ip is any or multicast
     * use the outgoing network interface IP address as source address */
    src_ip = netif_ip_addr4(netif);
  } else {
    /* check if UDP PCB local IP address is correct
     * this could be an old address if netif->ip_addr has changed */
    if (!ip4_addr_cmp(ip_2_ip4(&(pcb->local_ip)), netif_ip4_addr(netif))) {
      /* local_ip doesn't match, drop the packet */
      rakis_rwlock_read_unlock(&pcb->pcb_lock);
      return ERR_RTE;
    }
    /* use UDP PCB local IP address as source address */
    src_ip = &pcb->local_ip;
  }

  struct udp_hdr *udphdr;
  err_t err;
  struct pbuf *q; /* q will be sent down the stack */
  u8_t ip_proto;
  u8_t ttl;

  if (!IP_ADDR_PCB_VERSION_MATCH(pcb, dst_ip)) {
    rakis_rwlock_read_unlock(&pcb->pcb_lock);
    return ERR_VAL;
  }

  /* if the PCB is not yet bound to a port, bind it here */
  if (pcb->local_port == 0) {
    rakis_rwlock_read_unlock(&pcb->pcb_lock);
    rakis_rwlock_write_lock(&udp_pcbs_lock);
    rakis_rwlock_write_lock(&pcb->pcb_lock);
    if (pcb->local_port == 0) { // we have to check again here to not enter bind twice
      LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_send: not yet bound to a port, binding now\n"));
      err = udp_bind_locked(pcb, &pcb->local_ip, pcb->local_port);
      if (err != ERR_OK) {
        LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("udp_send: forced port bind failed\n"));
        rakis_rwlock_write_unlock(&pcb->pcb_lock);
        rakis_rwlock_write_unlock(&udp_pcbs_lock);
        return err;
      }
    }
    rakis_rwlock_write_unlock(&pcb->pcb_lock);
    rakis_rwlock_write_unlock(&udp_pcbs_lock);
    rakis_rwlock_read_lock(&pcb->pcb_lock);
  }

  /* packet too large to add a UDP header without causing an overflow? */
  if ((u16_t)(p->tot_len + UDP_HLEN) < p->tot_len) {
    rakis_rwlock_read_unlock(&pcb->pcb_lock);
    return ERR_MEM;
  }

  /* allocate header in a separate new pbuf */
  q = pbuf_alloc(PBUF_IP, UDP_HLEN);
  /* new header pbuf could not be allocated? */
  if (q == NULL) {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("udp_send: could not allocate header\n"));
    rakis_rwlock_read_unlock(&pcb->pcb_lock);
    return ERR_MEM;
  }

  pbuf_chain(q, p);

  /* first pbuf q points to header pbuf */
  LWIP_DEBUGF(UDP_DEBUG,
      ("udp_send: added header pbuf %p before given pbuf %p\n", (void *)q, (void *)p));

  LWIP_ASSERT("check that first pbuf can hold struct udp_hdr",
              (q->len >= sizeof(struct udp_hdr)));
  /* q now represents the packet to be sent */
  udphdr = (struct udp_hdr *)q->payload;
  udphdr->src = lwip_htons(pcb->local_port);
  udphdr->dest = lwip_htons(dst_port);
  /* in UDP, 0 checksum means 'no checksum' */
  udphdr->chksum = 0x0000;

  LWIP_DEBUGF(UDP_DEBUG, ("udp_send: sending datagram of length %"U16_F"\n", q->tot_len));

  LWIP_DEBUGF(UDP_DEBUG, ("udp_send: UDP packet length %"U16_F"\n", q->tot_len));
  udphdr->len = lwip_htons(q->tot_len);
  /* calculate checksum */
  if ((RAKIS_GET_ATOMIC(&pcb->flags_atm) & UDP_FLAGS_NOCHKSUM) == 0) {
    u16_t udpchksum;
    udpchksum = ip_chksum_pseudo(q, IP_PROTO_UDP, q->tot_len,
        src_ip, dst_ip);

    /* chksum zero must become 0xffff, as zero means 'no checksum' */
    if (udpchksum == 0x0000) {
      udpchksum = 0xffff;
    }
    udphdr->chksum = udpchksum;
  }
  ip_proto = IP_PROTO_UDP;

  /* Determine TTL to use */
  ttl = RAKIS_GET_ATOMIC(&(pcb->ttl_atm));

  LWIP_DEBUGF(UDP_DEBUG, ("udp_send: UDP checksum 0x%04"X16_F"\n", udphdr->chksum));
  LWIP_DEBUGF(UDP_DEBUG, ("udp_send: ip_output_if (,,,,0x%02"X16_F",)\n", (u16_t)ip_proto));
  /* output to IP */
  err = ip_output_if_src(q, src_ip, dst_ip, ttl, RAKIS_GET_ATOMIC(&(pcb->tos_atm)), ip_proto, netif);

  /* did we chain a separate header pbuf earlier? */
  if (q != p) {
    /* free the header pbuf */
    pbuf_free(q);
    q = NULL;
    /* p is still referenced by the caller, and will live on */
  }

  rakis_rwlock_read_unlock(&pcb->pcb_lock);
  return err;
}

/**
 * @ingroup udp_raw
 * Bind an UDP PCB.
 * 
 * @param pcb UDP PCB to be bound with a local address ipaddr and port.
 * @param ipaddr local IP address to bind with. Use IP_ANY_TYPE to
 * bind to all local interfaces.
 * @param port local UDP port to bind with. Use 0 to automatically bind
 * to a random port between UDP_LOCAL_PORT_RANGE_START and
 * UDP_LOCAL_PORT_RANGE_END.
 *
 * ipaddr & port are expected to be in the same byte order as in the pcb.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occurred.
 * - ERR_USE. The specified ipaddr and port are already bound to by
 * another UDP PCB.
 *
 * @see udp_disconnect()
 */
err_t
udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{

  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (ipaddr == NULL) {
    ipaddr = IP4_ADDR_ANY;
  }

  LWIP_ERROR("udp_bind: invalid pcb", pcb != NULL, return ERR_ARG);

  rakis_rwlock_write_lock(&udp_pcbs_lock);
  rakis_rwlock_write_lock(&pcb->pcb_lock);
  err_t err = udp_bind_locked(pcb, ipaddr, port);
  rakis_rwlock_write_unlock(&pcb->pcb_lock);
  rakis_rwlock_write_unlock(&udp_pcbs_lock);
  return err;
}

/**
 * @ingroup udp_raw
 * Bind an UDP PCB to a specific netif.
 * After calling this function, all packets received via this PCB
 * are guaranteed to have come in via the specified netif, and all
 * outgoing packets will go out via the specified netif.
 *
 * @param pcb UDP PCB to be bound.
 * @param netif netif to bind udp pcb to. Can be NULL.
 *
 * @see udp_disconnect()
 */
void
udp_bind_netif(struct udp_pcb *pcb, const struct netif *netif)
{
  rakis_rwlock_write_lock(&pcb->pcb_lock);
  if (netif != NULL) {
    pcb->netif_idx = netif_get_index(netif);
  } else {
    pcb->netif_idx = NETIF_NO_INDEX;
  }
  rakis_rwlock_write_unlock(&pcb->pcb_lock);
}

/**
 * @ingroup udp_raw
 * Sets the remote end of the pcb. This function does not generate any
 * network traffic, but only sets the remote address of the pcb.
 *
 * @param pcb UDP PCB to be connected with remote address ipaddr and port.
 * @param ipaddr remote IP address to connect with.
 * @param port remote UDP port to connect with.
 *
 * @return lwIP error code
 *
 * ipaddr & port are expected to be in the same byte order as in the pcb.
 *
 * The udp pcb is bound to a random local port if not already bound.
 *
 * @see udp_disconnect()
 */
err_t
udp_connect(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{
  struct udp_pcb *ipcb;

  LWIP_ERROR("udp_connect: invalid pcb", pcb != NULL, return ERR_ARG);
  LWIP_ERROR("udp_connect: invalid ipaddr", ipaddr != NULL, return ERR_ARG);

  rakis_rwlock_write_lock(&udp_pcbs_lock);
  rakis_rwlock_write_lock(&pcb->pcb_lock);

  if (pcb->local_port == 0) {
    err_t err = udp_bind_locked(pcb, &pcb->local_ip, pcb->local_port);
    if (err != ERR_OK) {
      rakis_rwlock_write_unlock(&pcb->pcb_lock);
      rakis_rwlock_write_unlock(&udp_pcbs_lock);
      return err;
    }
  }

  ip_addr_set_ipaddr(&pcb->remote_ip, ipaddr);

  pcb->remote_port = port;
  RAKIS_OR_ATOMIC(&pcb->flags_atm, UDP_FLAGS_CONNECTED);

  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("udp_connect: connected to "));
  ip_addr_debug_print_val(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
                          pcb->remote_ip);
  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, (", port %"U16_F")\n", pcb->remote_port));

  /* Insert UDP PCB into the list of active UDP PCBs. */
  for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
    if (pcb == ipcb) {
      /* already on the list, just return */
      rakis_rwlock_write_unlock(&pcb->pcb_lock);
      rakis_rwlock_write_unlock(&udp_pcbs_lock);
      return ERR_OK;
    }
  }
  /* PCB not yet on the list, add PCB now */
  pcb->next = udp_pcbs;
  udp_pcbs = pcb;

  rakis_rwlock_write_unlock(&pcb->pcb_lock);
  rakis_rwlock_write_unlock(&udp_pcbs_lock);
  return ERR_OK;
}

/**
 * @ingroup udp_raw
 * Remove the remote end of the pcb. This function does not generate
 * any network traffic, but only removes the remote address of the pcb.
 *
 * @param pcb the udp pcb to disconnect.
 */
void
udp_disconnect(struct udp_pcb *pcb)
{
  LWIP_ERROR("udp_disconnect: invalid pcb", pcb != NULL, return);

  /* reset remote address association */
  rakis_rwlock_write_lock(&pcb->pcb_lock);
  ip_addr_set_any(IP_IS_V6_VAL(pcb->remote_ip), &pcb->remote_ip);
  pcb->remote_port = 0;
  pcb->netif_idx = NETIF_NO_INDEX;
  /* mark PCB as unconnected */
  udp_clear_flags(pcb, UDP_FLAGS_CONNECTED);
  rakis_rwlock_write_unlock(&pcb->pcb_lock);
}

/**
 * @ingroup udp_raw
 * Set a receive callback for a UDP PCB.
 * This callback will be called when receiving a datagram for the pcb.
 *
 * @param pcb the pcb for which to set the recv callback
 * @param recv function pointer of the callback function
 * @param recv_arg additional argument to pass to the callback function
 */
void
udp_set_recv_callback(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg)
{
  LWIP_ERROR("udp_recv: invalid pcb", pcb != NULL, return);

  rakis_rwlock_write_lock(&pcb->pcb_lock);
  /* remember recv() callback and user data */
  pcb->recv = recv;
  pcb->recv_arg = recv_arg;
  rakis_rwlock_write_unlock(&pcb->pcb_lock);
}

/**
 * @ingroup udp_raw
 * Removes and deallocates the pcb.  
 * 
 * @param pcb UDP PCB to be removed. The PCB is removed from the list of
 * UDP PCB's and the data structure is freed from memory.
 *
 * @see udp_new()
 */
void
udp_remove(struct udp_pcb *pcb)
{
  struct udp_pcb *pcb2;

  LWIP_ERROR("udp_remove: invalid pcb", pcb != NULL, return);
  rakis_rwlock_write_lock(&udp_pcbs_lock);

  /* pcb to be removed is first in list? */
  if (udp_pcbs == pcb) {
    /* make list start at 2nd pcb */
    udp_pcbs = udp_pcbs->next;
    /* pcb not 1st in list */
  } else {
    for (pcb2 = udp_pcbs; pcb2 != NULL; pcb2 = pcb2->next) {
      /* find pcb in udp_pcbs list */
      if (pcb2->next != NULL && pcb2->next == pcb) {
        /* remove pcb from list */
        pcb2->next = pcb->next;
        break;
      }
    }
  }
  rakis_rwlock_write_unlock(&udp_pcbs_lock);

  rakis_rwlock_destroy(&pcb->pcb_lock);
  mem_free(pcb);
}

/**
 * @ingroup udp_raw
 * Creates a new UDP pcb which can be used for UDP communication. The
 * pcb is not active until it has either been bound to a local address
 * or connected to a remote address.
 * @see MEMP_NUM_UDP_PCB
 *
 * @return The UDP PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @see udp_remove()
 */
struct udp_pcb *
udp_new(void)
{
  struct udp_pcb *pcb;

  pcb = (struct udp_pcb *)mem_malloc(sizeof(struct udp_pcb));
  /* could allocate UDP PCB? */
  if (pcb != NULL) {
    /* UDP Lite: by initializing to all zeroes, chksum_len is set to 0
     * which means checksum is generated over the whole datagram per default
     * (recommended as default by RFC 3828). */
    /* initialize PCB to all zeroes */
    memset(pcb, 0, sizeof(struct udp_pcb));
    RAKIS_SET_ATOMIC(&(pcb->ttl_atm), UDP_TTL);
    rakis_rwlock_create(&pcb->pcb_lock);
  }
  return pcb;
}

/**
 * @ingroup udp_raw
 * Create a UDP PCB for specific IP type.
 * The pcb is not active until it has either been bound to a local address
 * or connected to a remote address.
 * @see MEMP_NUM_UDP_PCB
 *
 * @param type IP address type, see @ref lwip_ip_addr_type definitions.
 * If you want to listen to IPv4 and IPv6 (dual-stack) packets,
 * supply @ref IPADDR_TYPE_ANY as argument and bind to @ref IP_ANY_TYPE.
 * @return The UDP PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @see udp_remove()
 */
struct udp_pcb *
udp_new_ip_type(u8_t type)
{
  struct udp_pcb *pcb;

  pcb = udp_new();
  LWIP_UNUSED_ARG(type);
  return pcb;
}

#if UDP_DEBUG
/**
 * Print UDP header information for debug purposes.
 *
 * @param udphdr pointer to the udp header in memory.
 */
void
udp_debug_print(struct udp_hdr *udphdr)
{
  LWIP_DEBUGF(UDP_DEBUG, ("UDP header:\n"));
  LWIP_DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(UDP_DEBUG, ("|     %5"U16_F"     |     %5"U16_F"     | (src port, dest port)\n",
                          lwip_ntohs(udphdr->src), lwip_ntohs(udphdr->dest)));
  LWIP_DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(UDP_DEBUG, ("|     %5"U16_F"     |     0x%04"X16_F"    | (len, chksum)\n",
                          lwip_ntohs(udphdr->len), lwip_ntohs(udphdr->chksum)));
  LWIP_DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
}
#endif /* UDP_DEBUG */

#endif /* LWIP_UDP */
