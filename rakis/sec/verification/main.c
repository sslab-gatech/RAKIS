#include "rakis/rakis.h"
#include "rakis/xsk.h"
#include "rakis/pal.h"
#include "rakis/host_init.h"
#include "rakis/fv/ping_reply_server.h"
#include "rakis/io_uring.h"

#include <arpa/inet.h>
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "rakis/fv/host.h"
#include "rakis/fv/model.h"

// how many times to execute main loop in symbolic execution
#define SYM_EXEC_MAIN_LOOP_LIMIT 2

#define RAKIS_VERIFY_XSK_OR_IO_URING true // false for io_uring

// how many packets to echo in concrete execution before moving on
#define PACKET_ECHOED 5

struct rakis_config* g_rakis_config       = NULL;
struct rakis_per_thread_strg g_rakis_per_thread_strg;

struct rakis_io_uring*     g_rakis_io_uring = NULL;
struct rakis_io_uring_pool g_rakis_io_uring_pool;

#define IO_URING_TEST_FILE_NAME "/tmp/rakis-io-uring-test-file"

#ifndef RAKIS_SYMBOLIC
#define RAKIS_FV_RINGS_SIZE RAKIS_DEF_XDP_TX_RING_SIZE
#define RAKIS_FV_FRAME_SIZE RAKIS_DEF_XDP_FRAME_SIZE
#define RAKIS_FV_UMEM_SIZE  RAKIS_DEF_XDP_UMEM_SIZE
#else
// kernel enforces minimum umem size that is too big for
// feasibility of symbolic execution..
#define RAKIS_FV_RINGS_SIZE 2
#define RAKIS_FV_FRAME_SIZE 512
#define RAKIS_FV_UMEM_SIZE  8 * RAKIS_FV_FRAME_SIZE
#endif

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
  xsk_cfg->fill_ring_size       = RAKIS_FV_RINGS_SIZE * 2;
  xsk_cfg->compl_ring_size      = RAKIS_FV_RINGS_SIZE;
  xsk_cfg->rx_ring_size         = RAKIS_FV_RINGS_SIZE;
  xsk_cfg->tx_ring_size         = RAKIS_FV_RINGS_SIZE;
  xsk_cfg->frame_size           = RAKIS_FV_FRAME_SIZE;
  xsk_cfg->umem_size            = RAKIS_FV_UMEM_SIZE;
  xsk_cfg->zero_copy            = true;
  xsk_cfg->needs_wakeup         = false;

  g_rakis_config->net_threads_num = 1;
  g_rakis_config->total_xsks_num  = 1;
  g_rakis_config->io_urings_cfg.io_urings_num = 1;
  g_rakis_config->io_urings_cfg.entries_num  = RAKIS_FV_RINGS_SIZE;
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

static void rakis_fv_io_uring(struct rakis_pal* rakis_pal){
  int ret = rakis_init_pal_io_urings(&g_rakis_config->io_urings_cfg, rakis_pal);
  if(ret < 0){
    err(EXIT_FAILURE, "Could not initialize rakis io_uring");
  }

  int fd = 0;
#ifndef RAKIS_SYMBOLIC
  fd = open(IO_URING_TEST_FILE_NAME, O_CREAT | O_RDWR, 0644);
  if(fd < 0){
    err(EXIT_FAILURE, "Could not open file %s", IO_URING_TEST_FILE_NAME);
  }
#endif

  char wbuf[13] = "Hello World!";
  ret = rakis_io_uring_write(fd, wbuf, 13, 0);
  if(ret < 0){
    err(EXIT_FAILURE, "Could not write to file %s", IO_URING_TEST_FILE_NAME);
  }

  char rbuf[13];
#ifdef RAKIS_SYMBOLIC
  klee_make_symbolic(rbuf, 13, "rbuf");
#endif

  ret = rakis_io_uring_read(fd, rbuf, 13, 0);
  if(ret < 0){
    err(EXIT_FAILURE, "Could not read from file %s", IO_URING_TEST_FILE_NAME);
  }

  if(strcmp(wbuf, rbuf) != 0){
    err(EXIT_FAILURE, "IO_URING test failed");
  }else{
    printf("IO_URING test passed\n");
  }
}

static void rakis_fv_xsk(struct rakis_pal* rakis_pal){/*{{{*/
  // we first start by initializing our xsk manager
  if(rakis_init_netifs(rakis_pal) < 0){
    err(EXIT_FAILURE, "Could not initialize rakis netifs");
  }

  struct rakis_xsk* xsk = rakis_xsk_get_xsk(g_rakis_netifs[0].xsks, 0);

#ifdef RAKIS_SYMBOLIC
  struct rakis_ring_prod* fill_ring = rakis_xsk_get_prod_fill_ring(xsk);
  struct rakis_ring_cons* compl_ring = rakis_xsk_get_cons_compl_ring(xsk);
  struct rakis_ring_prod* tx_ring = rakis_xsk_get_prod_tx_ring(xsk);
  struct rakis_ring_cons* rx_ring = rakis_xsk_get_cons_rx_ring(xsk);

  // verify initial ring values
  rakis_fv_verify_prod_ring(fill_ring);
  rakis_fv_verify_cons_ring(compl_ring);
  rakis_fv_verify_prod_ring(tx_ring);
  rakis_fv_verify_cons_ring(rx_ring);

  for(int i=0; i < SYM_EXEC_MAIN_LOOP_LIMIT; i++){
    rakis_xsk_tick(xsk);
    rakis_test_ping_reply_server(xsk);
  }
#else
  // this loop is infinite in sym-exec.. because in reality, we could wait
  // forever waiting for packets to arrive, and there will be a symbolic value
  // to reflect that.

  for(int i=0; i < PACKET_ECHOED;){
    rakis_xsk_tick(xsk);
    int s = rakis_test_ping_reply_server(xsk);
    if(s){
      sendto(rakis_xsk_get_fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
      i+=s;
    }
  }
#endif

  // verify final ring values
  rakis_fv_verify_prod_ring(fill_ring);
  rakis_fv_verify_cons_ring(compl_ring);
  rakis_fv_verify_prod_ring(tx_ring);
  rakis_fv_verify_cons_ring(rx_ring);
}/*}}}*/

int main(int argc, char** args){
  int ret = 0;

  // prepare rakis config
  prep_rakis_cfg();

  // allocate rakis pal
  struct rakis_pal* rakis_pal = alloc_rakis_pal();
  if(!rakis_pal){
    err(EXIT_FAILURE, "Could not allocate for rakis_pal");
  }

#ifdef RAKIS_SYMBOLIC
  // for symbolic execution, we model the rakis_pal values
  rakis_fv_model_monitor_memory(g_rakis_config, rakis_pal);
  rakis_fv_model_xsk_memory(g_rakis_config, &rakis_pal->netifs[0]);
  rakis_fv_model_io_uring_memory(g_rakis_config, &rakis_pal->io_urings[0]);
#else
  // for concrete execution, we initialize the xsk socket
  ret = rakis_host_init(g_rakis_config, rakis_pal);
  if (ret < 0) {
    err(EXIT_FAILURE, "Could not initialize XDP socket");
  }
#endif

  // verify XDP socket data
  ret = rakis_initialization_data_checker(g_rakis_config, rakis_pal);
  if(ret < 0){
    err(EXIT_FAILURE, "OMG!! Malicious host!.. RAKIS Could not verify XDP initialization results");
  }

#if RAKIS_VERIFY_XSK_OR_IO_URING
  // verify XSK
  log_debug("Verifying XSK");
  rakis_fv_xsk(rakis_pal);
#else
  // verify io_uring
  log_debug("Verifying io_uring");
  rakis_fv_io_uring(rakis_pal);
#endif

  return 0;
}
