#include "rakis/netif.h"
#include "rakis/xsk.h"

#ifdef RAKIS_VERIFICATION
#include "rakis/fv/host.h"
#else
#ifdef RAKIS_FUZZ
#include "rakis/fuzz/log.h"
#else
#include "libos_utils.h"
#endif
#endif

struct rakis_netif* g_rakis_netifs = NULL;

static int rakis_init_netif(struct rakis_netif_cfg* rakis_netif_cfg,
    struct rakis_netif_pal* rakis_netif_pal,
    struct rakis_netif* rakis_netif){

  rakis_netif->ifindex = rakis_netif_pal->ifindex;
  rakis_netif->netif_cfg  = rakis_netif_cfg;

  rakis_netif->xsks_num = rakis_netif_cfg->xsks_num;
  rakis_netif->xsks = rakis_xsk_alloc_xsks(rakis_netif_cfg->xsks_num);
  if (!rakis_netif->xsks) {
    log_error("calloc failed for netif->xsks");
    return -1;
  }

  for (u32 i=0; i < rakis_netif->xsks_num; i++) {
    if(rakis_new_xsk(
          &rakis_netif_cfg->xsks_cfg[i],
          &rakis_netif_pal->xsks[i],
          rakis_netif,
          rakis_xsk_get_xsk(rakis_netif->xsks, i)) < 0){
      log_error("Could not create new xsk");
      return -1;
    }
  }

  return 0;
}

int rakis_init_netifs(struct rakis_pal* rakis_pal){
  int ret;

  g_rakis_netifs = calloc(g_rakis_config->netifs_num, sizeof(struct rakis_netif));
  if (!g_rakis_netifs) {
    log_error("calloc failed for g_rakis_netifs");
    return -1;
  }

  for (u32 i=0; i < g_rakis_config->netifs_num; i++) {
    ret = rakis_init_netif(&g_rakis_config->netifs_cfg[i], &rakis_pal->netifs[i], &g_rakis_netifs[i]);
    if (ret < 0) {
      log_error("Could not create new netif");
      return ret;
    }
  }

  return 0;
}
