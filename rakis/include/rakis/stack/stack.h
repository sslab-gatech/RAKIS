#include "lwip/netif.h"
#include "rakis/pktq.h"
#include "rakis/rakis.h"

void rakis_stack_process_rx(struct netif* netif, struct pktq* pktq);
int rakis_stack_init(void);
