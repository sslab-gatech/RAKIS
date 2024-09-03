/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * Copyright (c) 2003-2004 Leon Woestenberg <leon.woestenberg@axon.tv>
 * Copyright (c) 2003-2004 Axon Digital Design B.V., The Netherlands.
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
 */

#include "lwip/opt.h"

#include "lwip/etharp.h"
#include "lwip/ethernet.h"
#include "lwip/prot/iana.h"
#include "rakis/stack/rakis_misc.h"

#include <string.h>

/** ARP states */
enum etharp_state {
  ETHARP_STATE_EMPTY = 0,
  ETHARP_STATE_STATIC
};

struct etharp_entry {
  ip4_addr_t ipaddr;
  struct netif *netif;
  struct eth_addr ethaddr;
  u8_t state;
};

static struct etharp_entry static_arp_table[ARP_TABLE_SIZE];

#define ETHARP_SET_ADDRHINT(addrhint) (RAKIS_GET_THREAD_STRG(etharp_cached_entry) = (addrhint))
#define ETHARP_GET_ADDRHINT()         (RAKIS_GET_THREAD_STRG(etharp_cached_entry))

/** Try hard to create a new entry - we want the IP address to appear in
    the cache (even if this means removing an active entry or so). */
#define ETHARP_FLAG_FIND_ONLY    2
#define ETHARP_FLAG_STATIC_ENTRY 4

/* Check for maximum ARP_TABLE_SIZE */
#if (ARP_TABLE_SIZE > NETIF_ADDR_IDX_MAX)
#error "ARP_TABLE_SIZE must fit in an s16_t, you have to reduce it in your lwipopts.h"
#endif

/**
 * Send a raw ARP packet (opcode and all addresses can be modified)
 *
 * @param netif the lwip network interface on which to send the ARP packet
 * @param ethsrc_addr the source MAC address for the ethernet header
 * @param ethdst_addr the destination MAC address for the ethernet header
 * @param hwsrc_addr the source MAC address for the ARP protocol header
 * @param ipsrc_addr the source IP address for the ARP protocol header
 * @param hwdst_addr the destination MAC address for the ARP protocol header
 * @param ipdst_addr the destination IP address for the ARP protocol header
 * @param opcode the type of the ARP packet
 * @return ERR_OK if the ARP packet has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other err_t on failure
 */
static err_t
etharp_raw(struct netif *netif, const struct eth_addr *ethsrc_addr,
           const struct eth_addr *ethdst_addr,
           const struct eth_addr *hwsrc_addr, const ip4_addr_t *ipsrc_addr,
           const struct eth_addr *hwdst_addr, const ip4_addr_t *ipdst_addr,
           const u16_t opcode)
{
  struct pbuf *p;
  err_t result = ERR_OK;
  struct etharp_hdr *hdr;

  LWIP_ASSERT("netif != NULL", netif != NULL);

  /* allocate a pbuf for the outgoing ARP request packet */
  p = pbuf_alloc(PBUF_LINK, SIZEOF_ETHARP_HDR);
  /* could allocate a pbuf for an ARP request? */
  if (p == NULL) {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("etharp_raw: could not allocate pbuf for ARP request.\n"));
    return ERR_MEM;
  }
  LWIP_ASSERT("check that first pbuf can hold struct etharp_hdr",
              (p->len >= SIZEOF_ETHARP_HDR));

  hdr = (struct etharp_hdr *)p->payload;
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_raw: sending raw ARP packet.\n"));
  hdr->opcode = lwip_htons(opcode);

  LWIP_ASSERT("netif->hwaddr_len must be the same as ETH_HWADDR_LEN for etharp!",
              (netif->hwaddr_len == ETH_HWADDR_LEN));

  /* Write the ARP MAC-Addresses */
  SMEMCPY(&hdr->shwaddr, hwsrc_addr, ETH_HWADDR_LEN);
  SMEMCPY(&hdr->dhwaddr, hwdst_addr, ETH_HWADDR_LEN);
  /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers without
   * structure packing. */
  IPADDR_WORDALIGNED_COPY_FROM_IP4_ADDR_T(&hdr->sipaddr, ipsrc_addr);
  IPADDR_WORDALIGNED_COPY_FROM_IP4_ADDR_T(&hdr->dipaddr, ipdst_addr);

  hdr->hwtype = PP_HTONS(LWIP_IANA_HWTYPE_ETHERNET);
  hdr->proto = PP_HTONS(ETHTYPE_IP);
  /* set hwlen and protolen */
  hdr->hwlen = ETH_HWADDR_LEN;
  hdr->protolen = sizeof(ip4_addr_t);

  /* send ARP query */
  ethernet_output(netif, p, ethsrc_addr, ethdst_addr, ETHTYPE_ARP);

  /* free ARP query packet */
  pbuf_free(p);
  p = NULL;
  /* could not allocate pbuf for ARP request */

  return result;
}

static s16_t
etharp_find_entry(const ip4_addr_t *ipaddr, u8_t flags, struct netif *netif)
{
  s16_t empty = ARP_TABLE_SIZE;
  s16_t i = 0;

  for (i = 0; i < ARP_TABLE_SIZE; ++i) {
    u8_t state = static_arp_table[i].state;
    if ((empty == ARP_TABLE_SIZE) && (state == ETHARP_STATE_EMPTY)) {
      LWIP_DEBUGF(ETHARP_DEBUG, ("etharp_find_entry: found empty entry %d\n", (int)i));
      empty = i;
    } else if (state == ETHARP_STATE_STATIC) {
      if (ipaddr && ip4_addr_cmp(ipaddr, &static_arp_table[i].ipaddr)
          && ((netif == NULL) || (netif == static_arp_table[i].netif))){
        LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: found matching entry %d\n", (int)i));
        /* found exact IP address match, simply bail out */
        return i;
      }
    }
  }

  // dont create, just search but we have not find anything
  if (((flags & ETHARP_FLAG_FIND_ONLY) != 0)){
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: did not find arp entry\n"));
    return (s16_t)ERR_MEM;
  }

  // we should create but our table is full
  if(empty == ARP_TABLE_SIZE) {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: no empty entry found\n"));
    return (s16_t)ERR_MEM;
  }

  // create new entry on the empty slot
  i = empty;
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: selecting empty entry %d\n", (int)i));
  LWIP_ASSERT("i < ARP_TABLE_SIZE", i < ARP_TABLE_SIZE);
  LWIP_ASSERT("arp_table[i].state == ETHARP_STATE_EMPTY",
      static_arp_table[i].state == ETHARP_STATE_EMPTY);

  /* IP address given? */
  if (ipaddr != NULL) {
    /* set IP address */
    ip4_addr_copy(static_arp_table[i].ipaddr, *ipaddr);
  }
  static_arp_table[i].netif = netif;
  return (s16_t)i;
}

static err_t
etharp_update_arp_entry(struct netif *netif, const ip4_addr_t *ipaddr, struct eth_addr *ethaddr, u8_t flags)
{
  s16_t i;
  LWIP_ASSERT("netif->hwaddr_len == ETH_HWADDR_LEN", netif->hwaddr_len == ETH_HWADDR_LEN);
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_update_arp_entry: %"U16_F".%"U16_F".%"U16_F".%"U16_F" - %02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F"\n",
              ip4_addr1_16(ipaddr), ip4_addr2_16(ipaddr), ip4_addr3_16(ipaddr), ip4_addr4_16(ipaddr),
              (u16_t)ethaddr->addr[0], (u16_t)ethaddr->addr[1], (u16_t)ethaddr->addr[2],
              (u16_t)ethaddr->addr[3], (u16_t)ethaddr->addr[4], (u16_t)ethaddr->addr[5]));
  /* non-unicast address? */
  if (ip4_addr_isany(ipaddr) ||
      ip4_addr_isbroadcast(ipaddr, netif) ||
      ip4_addr_ismulticast(ipaddr)) {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_update_arp_entry: will not add non-unicast IP address to ARP cache\n"));
    return ERR_ARG;
  }

  /* find or create ARP entry */
  i = etharp_find_entry(ipaddr, flags, netif);
  /* bail out if no entry could be found */
  if (i < 0) {
    return (err_t)i;
  }

  if (static_arp_table[i].state == ETHARP_STATE_STATIC) {
    /* found entry is a static type, don't overwrite it */
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_update_arp_entry: duplicate static arp entry\n"));
    return ERR_VAL;
  }

  /* record static type */
  static_arp_table[i].state = ETHARP_STATE_STATIC;
  /* record network interface */
  static_arp_table[i].netif = netif;
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_update_arp_entry: updating static entry %"S16_F"\n", i));
  /* update address */
  SMEMCPY(&static_arp_table[i].ethaddr, ethaddr, ETH_HWADDR_LEN);
  return ERR_OK;
}

err_t
etharp_add_static_entry(const ip4_addr_t *ipaddr, struct eth_addr *ethaddr)
{
  struct netif *netif;
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_add_static_entry: %"U16_F".%"U16_F".%"U16_F".%"U16_F" - %02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F"\n",
              ip4_addr1_16(ipaddr), ip4_addr2_16(ipaddr), ip4_addr3_16(ipaddr), ip4_addr4_16(ipaddr),
              (u16_t)ethaddr->addr[0], (u16_t)ethaddr->addr[1], (u16_t)ethaddr->addr[2],
              (u16_t)ethaddr->addr[3], (u16_t)ethaddr->addr[4], (u16_t)ethaddr->addr[5]));

  netif = ip4_route(ipaddr);
  if (netif == NULL) {
    return ERR_RTE;
  }

  return etharp_update_arp_entry(netif, ipaddr, ethaddr, ETHARP_FLAG_STATIC_ENTRY);
}

void
etharp_input(struct pbuf *p, struct netif *netif)
{
  struct etharp_hdr *hdr;
  /* these are aligned properly, whereas the ARP header fields might not be */
  ip4_addr_t sipaddr, dipaddr;
  u8_t for_us;

  LWIP_ERROR("netif != NULL", (netif != NULL), return;);

  hdr = (struct etharp_hdr *)p->payload;

  /* RFC 826 "Packet Reception": */
  if ((hdr->hwtype != PP_HTONS(LWIP_IANA_HWTYPE_ETHERNET)) ||
      (hdr->hwlen != ETH_HWADDR_LEN) ||
      (hdr->protolen != sizeof(ip4_addr_t)) ||
      (hdr->proto != PP_HTONS(ETHTYPE_IP)))  {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
                ("etharp_input: packet dropped, wrong hw type, hwlen, proto, protolen or ethernet type (%"U16_F"/%"U16_F"/%"U16_F"/%"U16_F")\n",
                 hdr->hwtype, (u16_t)hdr->hwlen, hdr->proto, (u16_t)hdr->protolen));
    pbuf_free(p);
    return;
  }

  /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers without
   * structure packing (not using structure copy which breaks strict-aliasing rules). */
  IPADDR_WORDALIGNED_COPY_TO_IP4_ADDR_T(&sipaddr, &hdr->sipaddr);
  IPADDR_WORDALIGNED_COPY_TO_IP4_ADDR_T(&dipaddr, &hdr->dipaddr);

  /* this interface is not configured? */
  if (ip4_addr_isany_val(*netif_ip4_addr(netif))) {
    for_us = 0;
  } else {
    /* ARP packet directed to us? */
    for_us = (u8_t)ip4_addr_cmp(&dipaddr, netif_ip4_addr(netif));
  }

  /* now act on the message itself */
  switch (hdr->opcode) {
    /* ARP request? */
    case PP_HTONS(ARP_REQUEST):
      /* ARP request. If it asked for our address, we send out a
       * reply. In any case, we time-stamp any existing ARP entry,
       * and possibly send out an IP packet that was queued on it. */

      LWIP_DEBUGF (ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: incoming ARP request\n"));
      /* ARP request for our address? */
      if (for_us) {
        /* send ARP response */
        etharp_raw(netif,
                   (struct eth_addr *)netif->hwaddr, &hdr->shwaddr,
                   (struct eth_addr *)netif->hwaddr, netif_ip4_addr(netif),
                   &hdr->shwaddr, &sipaddr,
                   ARP_REPLY);
        /* we are not configured? */
      } else if (ip4_addr_isany_val(*netif_ip4_addr(netif))) {
        /* { for_us == 0 and netif->ip_addr.addr == 0 } */
        LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: we are unconfigured, ARP request ignored.\n"));
        /* request was not directed to us */
      } else {
        /* { for_us == 0 and netif->ip_addr.addr != 0 } */
        LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: ARP request was not for us.\n"));
      }
      break;
    case PP_HTONS(ARP_REPLY):
      /* ARP reply. We already updated the ARP cache earlier. */
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: incoming ARP reply\n"));
      break;
    default:
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: ARP unknown opcode type %"S16_F"\n", lwip_htons(hdr->opcode)));
      break;
  }
  /* free ARP packet */
  pbuf_free(p);
}

static err_t
etharp_output_to_arp_index(struct netif *netif, struct pbuf *q, netif_addr_idx_t arp_idx)
{
  return ethernet_output(netif, q, (struct eth_addr *)(netif->hwaddr), &static_arp_table[arp_idx].ethaddr, ETHTYPE_IP);
}

err_t
etharp_output(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr)
{
  const struct eth_addr *dest;
  struct eth_addr mcastaddr;
  const ip4_addr_t *dst_addr = ipaddr;

  LWIP_ASSERT("netif != NULL", netif != NULL);
  LWIP_ASSERT("q != NULL", q != NULL);
  LWIP_ASSERT("ipaddr != NULL", ipaddr != NULL);

  /* Determine on destination hardware address. Broadcasts and multicasts
   * are special, other IP addresses are looked up in the ARP table. */

  /* broadcast destination IP address? */
  if (ip4_addr_isbroadcast(ipaddr, netif)) {
    /* broadcast on Ethernet also */
    dest = (const struct eth_addr *)&ethbroadcast;
    /* multicast destination IP address? */
  } else if (ip4_addr_ismulticast(ipaddr)) {
    /* Hash IP multicast address to MAC address.*/
    mcastaddr.addr[0] = LL_IP4_MULTICAST_ADDR_0;
    mcastaddr.addr[1] = LL_IP4_MULTICAST_ADDR_1;
    mcastaddr.addr[2] = LL_IP4_MULTICAST_ADDR_2;
    mcastaddr.addr[3] = ip4_addr2(ipaddr) & 0x7f;
    mcastaddr.addr[4] = ip4_addr3(ipaddr);
    mcastaddr.addr[5] = ip4_addr4(ipaddr);
    /* destination Ethernet address is multicast */
    dest = &mcastaddr;
    /* unicast destination IP address? */
  } else {
    netif_addr_idx_t i;
    /* outside local network? if so, this can neither be a global broadcast nor
       a subnet broadcast. */
    if (!ip4_addr_netcmp(ipaddr, netif_ip4_addr(netif), netif_ip4_netmask(netif)) &&
        !ip4_addr_islinklocal(ipaddr)) {
      /* interface has default gateway? */
      if (!ip4_addr_isany_val(*netif_ip4_gw(netif))) {
        /* send to hardware address of default gateway IP address */
        dst_addr = netif_ip4_gw(netif);
        /* no default gateway available */
      } else {
        /* no route to destination error (default gateway missing) */
        return ERR_RTE;
      }
    }

    if ((static_arp_table[ETHARP_GET_ADDRHINT()].netif == netif) &&
        (ip4_addr_cmp(dst_addr, &static_arp_table[ETHARP_GET_ADDRHINT()].ipaddr))) {
      return etharp_output_to_arp_index(netif, q, ETHARP_GET_ADDRHINT());
    }

    /* find stable entry: do this here since this is a critical path for
       throughput and etharp_find_entry() is kind of slow */
    for (i = 0; i < ARP_TABLE_SIZE; i++) {
      if ((static_arp_table[i].netif == netif) &&
          (ip4_addr_cmp(dst_addr, &static_arp_table[i].ipaddr))) {
        /* found an existing, stable entry */
        ETHARP_SET_ADDRHINT(i);
        return etharp_output_to_arp_index(netif, q, i);
      }
    }

    /* no stable entry found*/
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE,
        ("etharp_output: could not find arp entry for ip:%"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
          ip4_addr1_16(ipaddr), ip4_addr2_16(ipaddr), ip4_addr3_16(ipaddr), ip4_addr4_16(ipaddr)));
    return ERR_RTE;
  }

  /* continuation for multicast/broadcast destinations */
  /* obtain source Ethernet address of the given interface */
  /* send packet directly on the link */
  return ethernet_output(netif, q, (struct eth_addr *)(netif->hwaddr), dest, ETHTYPE_IP);
}
