#include "libos_thread.h"
#include "rakis/net_thread.h"
#include "rakis/netif.h"
#include "rakis/stack/rakis_misc.h"
#include "rakis/stack/stack.h"
#include "rakis/xsk.h"

struct libos_thread** g_rakis_net_threads = NULL;

int rakis_net_thread_main(u16 rakis_thread_id, struct libos_thread* this_thread, struct rakis_xsk** xsks, u32 num_xsks) {
  RAKIS_INC_ATOMIC(&g_rakis_config->status.initialized_threads);

  while(1){
    for (u32 i=0; i < num_xsks; i++) {
      struct rakis_xsk* xsk = xsks[i];
      struct pktq* pktq = rakis_xsk_get_pktq(xsk);

      rakis_xsk_tick(xsk);

      if (RAKIS_STRYLOCK(&pktq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_cons_lock))){
        rakis_stack_process_rx(rakis_xsk_get_lwip(xsk), pktq);
        RAKIS_SUNLOCK(&pktq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_cons_lock));
      }

    }

    if (RAKIS_GET_ATOMIC(&g_rakis_config->status.terminatation_flag)) {
      break;
    }
  }

  RAKIS_NET_THREAD_STAT_PRINT(rakis_thread_id, (void**)xsks, num_xsks);
  RAKIS_INC_ATOMIC(&g_rakis_config->status.terminated_threads);

  put_thread(this_thread);
  PalThreadExit(NULL);
}
