#ifndef RAKIS_MISC_H
#define RAKIS_MISC_H
#ifndef RAKIS_STAT

#define RAKIS_LOCK_STAT_INC(lock_stat, stat)
#define RAKIS_LOCK_STAT_DURATION_START(lock_stat, stat)
#define RAKIS_LOCK_STAT_DURATION_END(lock_stat, stat)

#define RAKIS_STAT_INC(stat)
#define RAKIS_STAT_DURATION_START(stat)
#define RAKIS_STAT_DURATION_END_PKT_CNT(stat, cnt)
#define RAKIS_STAT_DURATION_END(stat)
#define RAKIS_USER_THREAD_STAT_PRINT(thread, tid)
#define RAKIS_NET_THREAD_STAT_PRINT(tid, xsks, num_xsks)

#else
#include "rakis/common.h"

struct rakis_stat_duration{
  u64 count;
  u64 start;
  u64 average;
};

struct rakis_lock_stat{
  u64 tot_lock_attempts;
  u64 succ_lock_attempts;
  u64 fail_lock_attempts;

  struct rakis_stat_duration wait_time;
  struct rakis_stat_duration hold_time;
};

#define xsk_fill_duration_toggle             0
#define xsk_compl_duration_toggle            0
#define xsk_rx_duration_toggle               0
#define xsk_tick_duration_toggle             0
#define stack_single_process_duration_toggle 0
#define stack_batch_process_duration_toggle  0
#define ethernet_input_duration_toggle       0
#define pktbpool_alloc_duration_toggle       0
#define pktbpool_alloc_fill_duration_toggle  0
#define pkt_avg_process_duration_toggle      0
#define poll_event_duration_toggle           0
#define send_duration_toggle                 0
#define recv_duration_toggle                 0
#define locks_stat_toggle                    0

struct rakis_stat{
  struct rakis_stat_duration xsk_fill_duration;
  u64 xsk_fill_empty_alloc;
  u64 xsk_fill_full_ring;
  u64 xsk_fill_prod_frames;

  struct rakis_stat_duration xsk_compl_duration;
  u64 xsk_compl_empty_ring;
  u64 xsk_compl_invalid_frame;
  u64 xsk_compl_cons_frames;

  struct rakis_stat_duration xsk_rx_duration;
  u64 xsk_rx_empty_ring;
  u64 xsk_rx_full_pktq;
  u64 xsk_rx_invalid_frame;
  u64 xsk_rx_recv_frame;

  struct rakis_stat_duration xsk_tick_duration;
  struct rakis_stat_duration stack_single_process_duration;
  struct rakis_stat_duration stack_batch_process_duration;
  u64 stack_no_pkts;
  u64 stack_failed_process;

  struct rakis_stat_duration ethernet_input_duration;
  u64 ether_input_too_short;
  u64 ether_input_remove_header_failed;
  u64 ether_input_ip_packets;
  u64 ether_input_arp_packets;

  struct rakis_stat_duration pktbpool_alloc_duration;
  struct rakis_stat_duration pktbpool_alloc_fill_duration;
  u64 pktbpool_alloc_too_large;
  u64 pktbpool_alloc_fill_count;
  u64 pktbpool_alloc_nofill_count;
  u64 pktbpool_free_null;
  u64 pktbpool_free_pool;
  u64 pktbpool_free_pbuf;

  u64 pktq_enqueue_drop;
  u64 sockets_udp_callback_recv_pbuf;

  struct rakis_stat_duration pkt_avg_process_duration;

  struct rakis_stat_duration poll_event_duration;
  u64 poll_count;
  u64 poll_event_count;

  struct rakis_stat_duration send_duration;
  u64 send_count;

  struct rakis_stat_duration recv_duration;
  u64 recv_count;

  struct rakis_lock_stat xsk_fill_lock;
  struct rakis_lock_stat xsk_compl_lock;
  struct rakis_lock_stat xsk_rx_lock;
  struct rakis_lock_stat xsk_tx_lock;
  struct rakis_lock_stat xsk_alloc_lock;
  struct rakis_lock_stat xsk_pktq_prod_lock;
  struct rakis_lock_stat xsk_pktq_cons_lock;
  struct rakis_lock_stat sockets_pktq_prod_lock;
  struct rakis_lock_stat sockets_pktq_cons_lock;
  struct rakis_lock_stat pktbpool_lock;
  struct rakis_lock_stat sockets_poll_cb_lock;
  struct rakis_lock_stat sockets_fd_lock;
};

void rakis_set_time(u64* time);
void rakis_start_duration(struct rakis_stat_duration* duration);
void rakis_end_duration_per_pkt(struct rakis_stat_duration* duration, size_t pkt_count);
void rakis_end_duration(struct rakis_stat_duration* duration);
void rakis_user_thread_stat_print(struct rakis_stat* stat, u16 rakis_thread_id);
void rakis_net_thread_stat_print(struct rakis_stat* stat, u16 rakis_thread_id, void** xsks, u32 num_xsks);

#define RAKIS_LOCK_STAT_INC(lock_stat, stat) if(locks_stat_toggle && lock_stat){lock_stat->stat++;}
#define RAKIS_LOCK_STAT_DURATION_START(lock_stat, stat) if(locks_stat_toggle && lock_stat){rakis_start_duration(&(lock_stat->stat));}
#define RAKIS_LOCK_STAT_DURATION_END(lock_stat, stat) if(locks_stat_toggle && lock_stat){rakis_end_duration(&(lock_stat->stat));}

#define RAKIS_STAT_INC(stat) RAKIS_GET_THREAD_STRG(rakis_stats.stat)++
#define RAKIS_STAT_DURATION_START(stat) if(stat##_toggle) {rakis_start_duration(&(RAKIS_GET_THREAD_STRG(rakis_stats.stat)));}
#define RAKIS_STAT_DURATION_END_PKT_CNT(stat, cnt) if(stat##_toggle) {rakis_end_duration_per_pkt(&(RAKIS_GET_THREAD_STRG(rakis_stats.stat)), cnt);}
#define RAKIS_STAT_DURATION_END(stat) if(stat##_toggle) {rakis_end_duration(&(RAKIS_GET_THREAD_STRG(rakis_stats.stat)));}
#define RAKIS_USER_THREAD_STAT_PRINT(thread, tid) if(thread->rakis_per_thread_strg){rakis_user_thread_stat_print(&(thread->rakis_per_thread_strg->rakis_stats), tid);}
#define RAKIS_NET_THREAD_STAT_PRINT(tid, xsks, num_xsks) rakis_net_thread_stat_print(&RAKIS_GET_THREAD_STRG(rakis_stats), tid, xsks, num_xsks)

#endif

struct rakis_per_thread_strg{
  unsigned short etharp_cached_entry;
  int rerrno;

  struct pktbpool* mempool;

#ifdef RAKIS_STAT
  struct rakis_stat rakis_stats;
#endif
};

#if defined(RAKIS_VERIFICATION) || defined (RAKIS_FUZZ)
// during klee verification and fuzzing, we don't have threads, so we use a global variable
extern struct rakis_per_thread_strg g_rakis_per_thread_strg;
#define RAKIS_GET_THREAD_STRG(A) (g_rakis_per_thread_strg.A)
#else
struct rakis_per_thread_strg* rakis_get_per_thread_strg(void);
#define RAKIS_GET_THREAD_STRG(A) (((struct rakis_per_thread_strg*)rakis_get_per_thread_strg())->A)
#endif
#endif
