#include "lwip/etharp.h"
#include "lwip/ethernet.h"
#include "lwip/raw.h"
#include "lwip/udp.h"
#include "rakis/netif.h"
#include "rakis/stack/rakis_misc.h"
#include "rakis/stack/stack.h"
#include "rakis/xsk.h"

#ifndef RAKIS_FUZZ
#include "libos_utils.h"
#endif

static err_t rakis_netif_output(struct netif *netif, struct pbuf *p) {
#ifdef RAKIS_FUZZ
  log_debug("rakis_netif_output: sending %d bytes\n", p->tot_len);
  return ERR_OK;
#else
  struct rakis_netif *rakis_netif = netif->state;
  struct rakis_xsk* xsk = NULL;

  u32 tid = get_cur_tid();
  xsk = rakis_xsk_get_xsk(rakis_netif->xsks, tid % rakis_netif->xsks_num);

  u32 sent = rakis_xsk_send(xsk, p);

  return (sent <= p->tot_len) ? ERR_OK : ERR_IF;
#endif
}

static err_t rakis_netif_init_callback(struct netif* netif){
  struct rakis_netif* rakis_netif = netif->state;
  rakis_netif->lwip_netif = netif;
  netif->name[0] = rakis_netif->netif_cfg->interface_name[0];
  netif->name[1] = rakis_netif->netif_cfg->interface_name[1];
  netif->linkoutput = rakis_netif_output;
  netif->output = etharp_output;
  netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

  netif->mtu = rakis_netif->netif_cfg->mtu;
  return ERR_OK;
}

static int rakis_lwip_netif_add(struct rakis_netif* rakis_netif){
  struct netif* netif = calloc(1, sizeof(struct netif));
  if (!netif) {
    return -1;
  }
  rakis_netif->lwip_netif = netif;

  memcpy(netif->hwaddr, rakis_netif->netif_cfg->mac_addr, 6);
  netif->hwaddr_len = 6;

  netif_add(netif, (ip4_addr_t*)(&rakis_netif->netif_cfg->ip_addr),
      (ip4_addr_t*)(&rakis_netif->netif_cfg->netmask),
      (ip4_addr_t*)(&rakis_netif->netif_cfg->gw_addr),
      rakis_netif, rakis_netif_init_callback, NULL);

  return 0;
}

static int lwip_init_mods(void){
  int ret;

  ret = ip_init();
  if (ret < 0) {
    log_error("failed to init ip module");
    return -1;
  }

  ret = raw_init();
  if (ret < 0) {
    log_error("failed to init raw module");
    return -1;
  }

  ret = udp_init();
  if (ret < 0) {
    log_error("failed to init udp module");
    return -1;
  }

  ret = sockets_init();
  if (ret < 0) {
    log_error("failed to init udp module");
    return -1;
  }

  return 0;
}

void rakis_stack_process_rx(struct netif* netif, struct pktq* pktq){
  RAKIS_STAT_DURATION_START(stack_batch_process_duration);

  err_t err;
  u32 to_process = pktq_can_dequeue_cons_locked(pktq);
  if(to_process == 0){
    RAKIS_STAT_INC(stack_no_pkts);
    return;
  }

  for (u32 i = 0; i < to_process; i++) {
    RAKIS_STAT_DURATION_START(stack_single_process_duration);
    struct pbuf* p = pktq_dequeue_commit_cons_locked(pktq);
    err = ethernet_input(p, netif);
    if (err != ERR_OK) {
      RAKIS_STAT_INC(stack_failed_process);
      log_error("failed to process packet");
    }
    RAKIS_STAT_DURATION_END(stack_single_process_duration);
  }

  RAKIS_STAT_DURATION_END_PKT_CNT(pkt_avg_process_duration, to_process);

  pktq_dequeue_push_cons_locked(pktq);
  RAKIS_STAT_DURATION_END(stack_batch_process_duration);
}

int rakis_stack_init(void){
  int ret;
  // init the stack modules
  ret = lwip_init_mods();
  if (ret < 0) {
    log_error("failed to init lwip modules");
    return -1;
  }

  // add all interfaces
  for (u32 i=0; i < g_rakis_config->netifs_num; i++) {
    ret = rakis_lwip_netif_add(&g_rakis_netifs[i]);
    if(ret < 0){
      return -1;
    }
  }

  // set the arp table
  for (u32 i=0; i < g_rakis_config->arp_table_size; i++) {
    struct rakis_arp_entry* e = &g_rakis_config->arp_table[i];

    ip4_addr_t ip_addr = {e->ip_addr};
    struct eth_addr mac_addr;
    memcpy(&mac_addr, e->mac_addr, 6);

    ret = etharp_add_static_entry(&ip_addr, &mac_addr);
    if(ret < 0){
      log_error("failed to add static arp entry: %s, ignoring..", ip4addr_ntoa(&ip_addr));
    }else{
      log_debug("successfully added static arp entry: %s.", ip4addr_ntoa(&ip_addr));
    }
  }

  return 0;
}
