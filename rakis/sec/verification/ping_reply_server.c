#include "lwip/pbuf.h"
#include "rakis/fv/ping_reply_server.h"
#include "rakis/pktq.h"
#include "rakis/rakis.h"
#include "rakis/stack/rakis_spinlock.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#ifndef RAKIS_VERIFICATION
#include "libos_utils.h"
#else
#include "rakis/fv/host.h"
#endif

#define OUR_MAC {0x40, 0xa6, 0xb7, 0x40, 0x37, 0xf8}
#define OUR_IP  0xa320001

// Calculates the checksum
static unsigned short calc_checksum(unsigned short *ptr, int nbytes) {/*{{{*/
    unsigned long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        sum += *(unsigned char *)ptr;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}/*}}}*/

// Simply echo back the packet
static int rakis_test_ping_reply_server_handle_pkt(void* pkt, u32 len){/*{{{*/
  struct ethhdr* eth_hdr = (struct ethhdr*)pkt;
  struct iphdr* ip_hdr   = (struct iphdr*)(eth_hdr + 1);
  struct udphdr* udp_hdr = (struct udphdr*)(ip_hdr + 1);

  if(len < (sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*udp_hdr))){
    log_debug(">> RAKIS Ping Reply: Length not enough for eth+ip+udp");
    return 0;
  }

  if (__ntohs(eth_hdr->h_proto) != ETH_P_IP) {
    log_debug(">> RAKIS Ping Reply: ETH packet not IP");
    return 0;
  }

  if (memcmp(eth_hdr->h_dest, (uint8_t[6]) OUR_MAC, 6)) {
    log_debug(">> RAKIS Ping Reply: ETH packet not addressed to us");
    return 0;
  }

  u32 our_ip_n = __htonl(OUR_IP);
  if (our_ip_n != ip_hdr->daddr) {
    log_debug(">> RAKIS Ping Reply: IP packet not addressed to us: %x, %x\n", our_ip_n, ip_hdr->daddr);
    return 0;
  }

  if(ip_hdr->protocol != IPPROTO_UDP){
    log_debug(">> RAKIS Ping Reply: Not UDP packet");
    return 0;
  }

  if(ip_hdr->version != 4){
    log_debug(">> RAKIS Ping Reply: IP packet not version 4");
    return 0;
  }

  if(ip_hdr->ihl != 5){
    log_debug(">> RAKIS Ping Reply: IP packet header length not equal to 5");
    return 0;
  }

  size_t ip_payload_len = __ntohs(ip_hdr->tot_len) - sizeof(struct iphdr);
  if(ip_payload_len <= sizeof(struct udphdr)){
    log_debug(">> RAKIS Ping Reply: IP packet payload not enought for udp header");
    return 0;
  }

  if(ip_hdr->ttl == 0){
    log_debug(">> RAKIS Ping Reply: IP packet TTL expired");
    return 0;
  }

  if(calc_checksum((unsigned short*)ip_hdr, sizeof(struct iphdr))){
    log_debug(">> RAKIS Ping Reply: IP packet invalid checksum");
    return 0;
  }

  log_debug(">> RAKIS Ping Reply: Ping from %02x:%02x:%02x:%02x:%02x:%02x " \
      "(i.e %d.%d.%d.%d)\n",
      (unsigned char) eth_hdr->h_source[0],
      (unsigned char) eth_hdr->h_source[1],
      (unsigned char) eth_hdr->h_source[2],
      (unsigned char) eth_hdr->h_source[3],
      (unsigned char) eth_hdr->h_source[4],
      (unsigned char) eth_hdr->h_source[5],
      (unsigned char) (ip_hdr->saddr) & 0xff,
      (unsigned char) (ip_hdr->saddr >> 8) & 0xff,
      (unsigned char) (ip_hdr->saddr >> 16) & 0xff,
      (unsigned char) (ip_hdr->saddr >> 24) & 0xff);

  // eth source & dest
  memcpy(eth_hdr->h_dest, eth_hdr->h_source, ETH_ALEN);
  memcpy(eth_hdr->h_source, (uint8_t[6]) OUR_MAC, ETH_ALEN);

  // ip hdr
  memcpy(&ip_hdr->daddr, &ip_hdr->saddr, sizeof(ip_hdr->saddr));
  memcpy(&ip_hdr->saddr, &our_ip_n, sizeof(our_ip_n));
  ip_hdr->check = 0;
  ip_hdr->check = calc_checksum((unsigned short*)ip_hdr, sizeof(struct iphdr));

  // UDP echo reply
  u16 tmp_port = udp_hdr->dest;
  udp_hdr->dest = udp_hdr->source;
  udp_hdr->source = tmp_port;
  udp_hdr->check = 0;

  return ip_payload_len + sizeof(struct ethhdr) + sizeof(struct iphdr);
}/*}}}*/

int rakis_test_ping_reply_server(struct rakis_xsk* xsk){/*{{{*/
  struct pbuf* p = NULL;
  int slen=0;

  struct pktq* pktq = rakis_xsk_get_pktq(xsk);
  if (RAKIS_STRYLOCK(&pktq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_cons_lock))){
    u32 to_process = pktq_can_dequeue_cons_locked(pktq);
    if(to_process){
      p = pktq_dequeue_commit_cons_locked(pktq);
      pktq_dequeue_push_cons_locked(pktq);
    }

    RAKIS_SUNLOCK(&pktq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_cons_lock));
  }

  if (p) {
    log_debug(">> RAKIS Ping Reply: Received packet: %d", p->tot_len);

#ifdef RAKIS_SYMBOLIC
    // we do not want to waste time symbolically executing the ping server
    int prcslen = p->tot_len;

#else
    int prcslen = rakis_test_ping_reply_server_handle_pkt(p->payload, p->tot_len);
#endif

    if (prcslen) {
      slen = rakis_xsk_send(xsk, p);
      log_debug(">> RAKIS Ping Reply: sent packet: %d", slen);

    }else{
      log_debug(">> RAKIS Ping Reply: Dropping unknown packet");
    }

    pbuf_free(p);
  }

  return slen > 0 ? 1 : 0;
}/*}}}*/
