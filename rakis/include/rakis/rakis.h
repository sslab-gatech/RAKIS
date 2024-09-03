#ifndef RAKIS_H
#define RAKIS_H
#include "rakis/common.h"
#include "rakis/atomics.h"

#define RAKIS_STAT_CLOCK_ACCURACY_NS 1

// cacheline size is needed to verify the shared layout of the XDP ring pages
// we get from host os
#define RAKIS_CACHELINE_SIZE 64

// Default XDP values
#define RAKIS_DEF_XDP_NUM_OF_FRAMES   8192
#define RAKIS_DEF_XDP_TX_RING_SIZE    2048
#define RAKIS_DEF_XDP_RX_RING_SIZE    2048
#define RAKIS_DEF_XDP_FRAME_SIZE      2048
#define RAKIS_DEF_XDP_UMEM_SIZE       (RAKIS_DEF_XDP_NUM_OF_FRAMES * RAKIS_DEF_XDP_FRAME_SIZE)
#define RAKIS_DEF_XDP_MTU             1500

// Default io_uring values
#define RAKIS_DEF_IO_URING_ENTRIES     64

// Max number of FDs we can monitor
#define RAKIS_KFPS_NUM            512

// all configuration variables
struct rakis_config{

  struct rakis_status{
    bool enabled;

    u16  initialized_threads;
    bool initialization_done;

    u16  terminated_threads;
    bool terminatation_flag;
  } status;

  u32  netifs_num;
  struct rakis_netif_cfg{
    char interface_name[RAKIS_IFNAMSIZ];
    u32 ip_addr;
    u32 gw_addr;
    u32 netmask;
    u8  mac_addr[6];
    u16 mtu;

    u32 xsks_num;
    struct rakis_xsk_cfg{
      char ctrl_prcs_path[RAKIS_UNIX_PATH_MAX];
      u32  qid;

      u32 fill_ring_size;
      u32 compl_ring_size;
      u32 rx_ring_size;
      u32 tx_ring_size;

      u32 frame_size;
      u32 umem_size;

      bool zero_copy;
      bool needs_wakeup;
    } *xsks_cfg;
  } *netifs_cfg;

  u32  net_threads_num;
  u32  total_xsks_num;

  struct rakis_io_uring_cfg{
    u32 io_urings_num;
    u32 entries_num;
  } io_urings_cfg;

  u32 arp_table_size;
  struct rakis_arp_entry{
    u32 ip_addr;
    u8  mac_addr[6];
  } *arp_table;
};

#ifndef IN_PAL
extern struct rakis_config *g_rakis_config;
extern struct rakis_monitor_pal* g_rakis_monitor_pal;
extern struct libos_thread* g_monitor_thread;

#define RAKIS_IS_ENABLED() (g_rakis_config && g_rakis_config->status.enabled)
#define RAKIS_TERMINATE() do { \
  RAKIS_SET_ATOMIC(&g_rakis_config->status.terminatation_flag, true);\
  RAKIS_WAIT_UNTIL_ATOMIC_EQ(&g_rakis_config->status.terminated_threads, g_rakis_config->net_threads_num);\
  RAKIS_SET_ATOMIC(&g_rakis_config->status.enabled, false);\
  RAKIS_SET_ATOMIC(&g_rakis_monitor_pal->terminate_flag, true);\
  put_thread(g_monitor_thread); \
  } while(0)

int init_rakis(void);
#else

#define RAKIS_IS_ENABLED() (PalGetPalPublicState()->rakis_status && PalGetPalPublicState()->rakis_status->enabled)
#define RAKIS_IS_READY() (RAKIS_IS_ENABLED() && RAKIS_GET_ATOMIC(&PalGetPalPublicState()->rakis_status->initialization_done))
#endif

#endif
