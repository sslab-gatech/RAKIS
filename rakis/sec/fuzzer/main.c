#include "rakis/netif.h"
#include "rakis/pal.h"
#include "rakis/pktbpool.h"
#include "rakis/rakis.h"
#include "rakis/stack/stack.h"
#include "rakis/xsk.h"
#include "rakis/fuzz/log.h"
#include "rakis/fuzz/fuzz_sockets.h"

#include <arpa/inet.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Just a place holder, not actually used
#define RAKIS_FUZZ_RINGS_SIZE 1
#define RAKIS_FUZZ_FRAME_SIZE 1
#define RAKIS_FUZZ_UMEM_SIZE 1

struct rakis_config* g_rakis_config       = NULL;
struct rakis_per_thread_strg g_rakis_per_thread_strg;

u8_t pktbuf[50000];

static void prep_rakis_cfg(void){/*{{{*/
  // allocate for rakis_config
  g_rakis_config = calloc(1, sizeof(struct rakis_config));
  if(!g_rakis_config){
    err(EXIT_FAILURE, "Could not allocate for rakis_config");
  }

  // fill in rakis_config
  g_rakis_config->status.enabled = true;
  g_rakis_config->status.initialized_threads = 1;
  g_rakis_config->status.initialization_done = true;
  g_rakis_config->status.terminated_threads = 0;
  g_rakis_config->status.terminatation_flag = false;

  g_rakis_config->netifs_num = 1;
  g_rakis_config->netifs_cfg = calloc(g_rakis_config->netifs_num, sizeof(struct rakis_netif_cfg));
  if(!g_rakis_config->netifs_cfg){
    err(EXIT_FAILURE, "Could not allocate for g_rakis_config->netifs_cfg");
  }

  struct rakis_netif_cfg* netif_cfg = &g_rakis_config->netifs_cfg[0];
  strncpy(netif_cfg->interface_name, "ens5f0", RAKIS_IFNAMSIZ);
  netif_cfg->ip_addr = inet_addr("10.50.0.1");
  netif_cfg->gw_addr = inet_addr("10.50.0.1");
  netif_cfg->netmask = inet_addr("255.255.0.0");
  memcpy(netif_cfg->mac_addr, (uint8_t[6]){0x40, 0xa6, 0xb7, 0x40, 0x37, 0xf8}, 6);
  netif_cfg->mtu = 1500;
  netif_cfg->xsks_num = 1;
  netif_cfg->xsks_cfg = calloc(netif_cfg->xsks_num, sizeof(struct rakis_xsk_cfg));
  if(!netif_cfg->xsks_cfg){
    err(EXIT_FAILURE, "Could not allocate for netif_cfg->xsks_cfg");
  }

  struct rakis_xsk_cfg* xsk_cfg = &netif_cfg->xsks_cfg[0];
  strncpy(xsk_cfg->ctrl_prcs_path, "/tmp/rakis-xdp-def-ctrl", RAKIS_UNIX_PATH_MAX);
  xsk_cfg->qid                  = 0;
  xsk_cfg->fill_ring_size       = RAKIS_FUZZ_RINGS_SIZE * 2;
  xsk_cfg->compl_ring_size      = RAKIS_FUZZ_RINGS_SIZE;
  xsk_cfg->rx_ring_size         = RAKIS_FUZZ_RINGS_SIZE;
  xsk_cfg->tx_ring_size         = RAKIS_FUZZ_RINGS_SIZE;
  xsk_cfg->frame_size           = RAKIS_FUZZ_FRAME_SIZE;
  xsk_cfg->umem_size            = RAKIS_FUZZ_UMEM_SIZE;
  xsk_cfg->zero_copy            = true;
  xsk_cfg->needs_wakeup         = false;

  g_rakis_config->net_threads_num = 1;
  g_rakis_config->total_xsks_num  = 1;
  g_rakis_config->io_urings_cfg.io_urings_num = 1;
  g_rakis_config->io_urings_cfg.entries_num  = RAKIS_FUZZ_RINGS_SIZE;
  g_rakis_config->arp_table_size = 1;
  g_rakis_config->arp_table = calloc(g_rakis_config->arp_table_size, sizeof(struct rakis_arp_entry));
  if(!g_rakis_config->arp_table){
    err(EXIT_FAILURE, "Could not allocate for g_rakis_config->arp_table");
  }
  struct rakis_arp_entry* arp_entry = &g_rakis_config->arp_table[0];
  arp_entry->ip_addr = inet_addr("10.50.0.2");
  memcpy(arp_entry->mac_addr, (uint8_t[6]){0x40, 0xa6, 0xb7, 0x40, 0x37, 0xf9}, 6);
}/*}}}*/

static struct rakis_pal* alloc_rakis_pal(void){/*{{{*/
  struct rakis_pal* rakis_pal = calloc(1, sizeof(struct rakis_pal));
  if (!rakis_pal) {
    return NULL;
  }

  rakis_pal->netifs = calloc(g_rakis_config->netifs_num, sizeof(struct rakis_netif_pal));
  if (!rakis_pal->netifs) {
    return NULL;
  }

  for (u32 i = 0; i < g_rakis_config->netifs_num; i++) {
    struct rakis_netif_pal* rakis_netif_pal = &rakis_pal->netifs[i];
    rakis_netif_pal->xsks = calloc(g_rakis_config->netifs_cfg[i].xsks_num, sizeof(struct rakis_xsk_pal));
    if (!rakis_netif_pal->xsks) {
      return NULL;
    }
  }

  rakis_pal->io_urings = calloc(g_rakis_config->io_urings_cfg.io_urings_num, sizeof(struct rakis_io_uring_pal));
  if (!rakis_pal->io_urings) {
    return NULL;
  }
  return rakis_pal;
}/*}}}*/

// XSK phony implementation{{{
#define RAKIS_XSK_PKTQ_SIZE           128

struct rakis_xsk{
  struct pktbpool      *pktbpool;
  struct pktq          *pktq;
  struct rakis_xsk_cfg *cfg;
  struct rakis_netif   *rakis_netif;
};

void* rakis_xsk_get_lwip(struct rakis_xsk* xsk){
  return xsk->rakis_netif->lwip_netif;
}

struct rakis_xsk* rakis_xsk_get_xsk(struct rakis_xsk* xsks, int n){
  return &xsks[n];
}

struct rakis_xsk* rakis_xsk_alloc_xsks(int n){
  return calloc(n, sizeof(struct rakis_xsk));
}


int rakis_new_xsk(
    struct rakis_xsk_cfg* xsk_cfg,
    struct rakis_xsk_pal* xsk_pal,
    struct rakis_netif* rakis_netif,
    struct rakis_xsk* xsk){

  xsk->cfg         = xsk_cfg;
  xsk->rakis_netif = rakis_netif;

  if(!pktq_new(&xsk->pktq, RAKIS_XSK_PKTQ_SIZE)){
    log_error("RAKIS Failed to initialize incoming packets queue for xsk socket");
    return -1;
  }

  struct pktbpool* pktbpool = pktbpool_create(200);
  if(pktbpool == NULL){
    log_error("RAKIS Failed to initialize pktb pool for xsk socket");
    return -1;
  }
  xsk->pktbpool = pktbpool;

  return 0;
}/*}}}*/

static void rakis_fuzz_one(struct rakis_xsk* xsk, const u8_t* pktbuf, u32_t len){/*{{{*/
  struct pktq* pktq = xsk->pktq;

  RAKIS_SLOCK(&pktq->prod_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_prod_lock)));
  u32 can_recv = pktq_can_enqueue_prod_locked(pktq);
  if (can_recv == 0) {
    // our queue is full, we cannot receive any more packets
    RAKIS_SUNLOCK(&pktq->prod_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_prod_lock)));
    return;
  }

  struct pktb* pktb = pktb_malloc(xsk->pktbpool, len);
  if (pktb == NULL) {
    RAKIS_SUNLOCK(&pktq->prod_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_prod_lock)));
    err(EXIT_FAILURE, "Could not allocate for pktb");
  }

  memcpy(pktb->payload, pktbuf, len);
  pktq_enqueue_commit_prod_locked(pktq, (struct pbuf*)pktb);
  pktq_enqueue_push_prod_locked(pktq);
  RAKIS_SUNLOCK(&pktq->prod_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_prod_lock)));
}/*}}}*/

static void push_all_pkts(struct rakis_xsk* xsk, const u8_t *data, size_t len) {/*{{{*/
  const u16_t max_packet_size = 1514;
  const u8_t *ptr = data;
  size_t rem_len = len;

  while (rem_len > sizeof(u16_t)) {
    u16_t frame_len;
    memcpy(&frame_len, ptr, sizeof(u16_t));
    ptr += sizeof(u16_t);
    rem_len -= sizeof(u16_t);
    frame_len = htons(frame_len) & 0x7FF;
    frame_len = LWIP_MIN(frame_len, max_packet_size);
    if (frame_len > rem_len) {
      frame_len = (u16_t)rem_len;
    }
    if (frame_len != 0) {
      rakis_fuzz_one(xsk, ptr, frame_len);
    }
    ptr += frame_len;
    rem_len -= frame_len;
  }
}/*}}}*/

static void rakis_fuzz(struct rakis_xsk* xsk, const u8_t *data, size_t len) {/*{{{*/
  struct pktq* pktq = xsk->pktq;

  // we prepare the sockets
  if(prep_fuzz_sockets() < 0){
    err(EXIT_FAILURE, "Could not prepare fuzz sockets");
  }

  // split input into packets
  push_all_pkts(xsk, data, len);

  // process packets
  if (RAKIS_STRYLOCK(&pktq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_cons_lock))){
    rakis_stack_process_rx(rakis_xsk_get_lwip(xsk), pktq);
    RAKIS_SUNLOCK(&pktq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_cons_lock));
  }

  fuzz_sockets();
}/*}}}*/

int main(int argc, char** argv){
  // allocate the per thread storage
  g_rakis_per_thread_strg.mempool = pktbpool_create(50);

  // prepare rakis config
  prep_rakis_cfg();

  // allocate rakis pal
  struct rakis_pal* rakis_pal = alloc_rakis_pal();
  if(!rakis_pal){
    err(EXIT_FAILURE, "Could not allocate for rakis_pal");
  }

  // initialize our xsk manager
  if(rakis_init_netifs(rakis_pal) < 0){
    err(EXIT_FAILURE, "Could not initialize rakis netifs");
  }

  // initialize the network stack
  int ret = rakis_stack_init();
  if(ret < 0){
    err(EXIT_FAILURE, "Could not initialize RAKIS network stack");
  }


  struct rakis_xsk* xsk = rakis_xsk_get_xsk(g_rakis_netifs[0].xsks, 0);
  u32 input_len = fread(pktbuf, 1, sizeof(pktbuf), stdin);
  rakis_fuzz(xsk, pktbuf, input_len);

  free(xsk->pktq);
  free(rakis_pal->netifs[0].xsks);
  free(rakis_pal->netifs);
  free(rakis_pal->io_urings);
  free(rakis_pal);

  return 0;
}
