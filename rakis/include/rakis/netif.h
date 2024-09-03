#ifndef RAKIS_NETIF_H_
#define RAKIS_NETIF_H_
#include "rakis/pal.h"
#include "rakis/rakis.h"

struct rakis_netif{
  int ifindex;
  struct rakis_netif_cfg* netif_cfg;
  struct netif* lwip_netif;

  // the xsks attached to this interface
  u32 xsks_num;
  struct rakis_xsk *xsks;
};

extern struct rakis_netif* g_rakis_netifs;
int rakis_init_netifs(struct rakis_pal* rakis_pal);
#endif
