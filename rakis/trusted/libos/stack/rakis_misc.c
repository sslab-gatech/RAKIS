#include "libos_utils.h"
#include "pal.h"
#include "rakis/stack/rakis_misc.h"
#include "rakis/stack/rakis_spinlock.h"
#include "rakis/xsk.h"
#include "rakis/pktbpool.h"

#ifdef RAKIS_STAT
#if RAKIS_STAT_CLOCK_ACCURACY_NS == 1
#define CLOCK_UNIT "ns"
#else
#define CLOCK_UNIT "us"
#endif
#endif

struct rakis_spinlock write_lock;

struct rakis_per_thread_strg* rakis_get_per_thread_strg(void){
  struct libos_thread* this_thread = get_cur_thread();
  if(!this_thread->rakis_per_thread_strg){
    this_thread->rakis_per_thread_strg = calloc(1, sizeof(struct rakis_per_thread_strg));
    this_thread->rakis_per_thread_strg->mempool = pktbpool_create(50);
  }

  return this_thread->rakis_per_thread_strg;
}

#ifdef RAKIS_STAT
#if RAKIS_STAT_CLOCK_ACCURACY_NS == 1
static long do_syscall_c(long num, long arg0, long arg1, long arg2){
  long ret;
  __asm__ __volatile__ (
    "mov %1, %%rax\n\t"
    "mov %2, %%rdi\n\t"
    "mov %3, %%rsi\n\t"
    "mov %4, %%rdx\n\t"
    "syscall\n\t"
    "mov %%rax, %0\n\t"
    : "=r"(ret)
    : "r"(num), "r"(arg0), "r"(arg1), "r"(arg2)
    : "%rax", "%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9", "memory"
  );
  return ret;
}
#endif
#endif

#ifdef RAKIS_STAT
void rakis_set_time(u64* time){
#if RAKIS_STAT_CLOCK_ACCURACY_NS == 0
  PalSystemTimeQuery(time);
#else
  struct timespec tstart={0,0};
  do_syscall_c(__NR_clock_gettime, CLOCK_MONOTONIC, (long)&tstart, 0);
  *time = tstart.tv_sec * 1000000000 + tstart.tv_nsec;
#endif
}

void rakis_start_duration(struct rakis_stat_duration* duration){
  rakis_set_time(&duration->start);
}

void rakis_end_duration(struct rakis_stat_duration* duration){
  u64 tend;
  rakis_set_time(&tend);
  u64 duration_ns = tend - duration->start;
  duration->average = (duration->average * duration->count + duration_ns) / (duration->count + 1);
  duration->count++;
}

void rakis_end_duration_per_pkt(struct rakis_stat_duration* duration, size_t pkt_count){
  u64 tend;
  rakis_set_time(&tend);
  u64 duration_ns = (tend - duration->start)/pkt_count;
  duration->average = (duration->average * duration->count + duration_ns) / (duration->count + 1);
  duration->count++;
}

#define PRINT_TIME_STAT(name) if(name##_toggle){log_always("    - " #name ": %llu" CLOCK_UNIT, stat->name.average);}
#define PRINT_NUM_STAT(name)  if(stat->name){log_always("    - " #name ": %llu", stat->name);}
#define PRINT_LOCK_STAT(name) \
  if(stat->name.tot_lock_attempts){ \
    log_always("    - " #name ":"); \
    log_always("      - tot_lock_attempts: %llu", stat->name.tot_lock_attempts); \
    log_always("      - succ_lock_attempts: %llu (%llu%%)", stat->name.succ_lock_attempts, stat->name.succ_lock_attempts * 100 / stat->name.tot_lock_attempts); \
    log_always("      - fail_lock_attempts: %llu (%llu%%)", stat->name.fail_lock_attempts, stat->name.fail_lock_attempts * 100 / stat->name.tot_lock_attempts); \
    log_always("      - wait_time.average: %llu" CLOCK_UNIT, stat->name.wait_time.average); \
    log_always("      - hold_time.average: %llu" CLOCK_UNIT, stat->name.hold_time.average); \
  }


static void print_lock_stats(struct rakis_stat* stat){
  if (!locks_stat_toggle) {
    return;
  }

  log_always("  - Lock stats:");
  PRINT_LOCK_STAT(xsk_fill_lock);
  PRINT_LOCK_STAT(xsk_compl_lock);
  PRINT_LOCK_STAT(xsk_rx_lock);
  PRINT_LOCK_STAT(xsk_tx_lock);
  PRINT_LOCK_STAT(xsk_alloc_lock);
  PRINT_LOCK_STAT(xsk_pktq_prod_lock);
  PRINT_LOCK_STAT(xsk_pktq_cons_lock);
  PRINT_LOCK_STAT(sockets_pktq_prod_lock);
  PRINT_LOCK_STAT(sockets_pktq_cons_lock);
  PRINT_LOCK_STAT(pktbpool_lock);
  PRINT_LOCK_STAT(sockets_poll_cb_lock);
  PRINT_LOCK_STAT(sockets_fd_lock);
  log_always("");
}

void rakis_user_thread_stat_print(struct rakis_stat* stat, u16 rakis_thread_id){
  log_always("Printing RAKIS stat for user thread (%u):", rakis_thread_id);

  log_always("  - Poll stats:");
  PRINT_TIME_STAT(poll_event_duration);
  PRINT_NUM_STAT(poll_count);
  PRINT_NUM_STAT(poll_event_count);
  log_always("");

  log_always("  - Send stats");
  PRINT_TIME_STAT(send_duration);
  PRINT_NUM_STAT(send_count);
  log_always("");

  log_always("  - Recv stats");
  PRINT_TIME_STAT(recv_duration);
  PRINT_NUM_STAT(recv_count);
  log_always("");

  log_always("  - pktbpool stats");
  PRINT_TIME_STAT(pktbpool_alloc_duration);
  PRINT_TIME_STAT(pktbpool_alloc_fill_duration);
  PRINT_NUM_STAT(pktbpool_alloc_too_large);
  PRINT_NUM_STAT(pktbpool_alloc_fill_count);
  PRINT_NUM_STAT(pktbpool_alloc_nofill_count);
  PRINT_NUM_STAT(pktbpool_free_null);
  PRINT_NUM_STAT(pktbpool_free_pool);
  PRINT_NUM_STAT(pktbpool_free_pbuf);
  log_always("");

  print_lock_stats(stat);
}

void rakis_net_thread_stat_print(struct rakis_stat* stat, u16 rakis_thread_id, void** xsks, u32 num_xsks){
  RAKIS_SLOCK(&write_lock, NULL);
  log_always("Printing RAKIS stat for net thread (%u):", rakis_thread_id);

  log_always("  - num_xsks: %u", num_xsks);
  for (u32 i=0; i < num_xsks; i++) {
    struct rakis_xsk* xsk = ((struct rakis_xsk**)xsks)[i];
    log_always("    - xsk qid: %u", xsk->qid);
  }
  log_always("");

  log_always("  - XSK Fill stats");
  PRINT_TIME_STAT(xsk_fill_duration);
  PRINT_NUM_STAT(xsk_fill_empty_alloc);
  PRINT_NUM_STAT(xsk_fill_full_ring);
  PRINT_NUM_STAT(xsk_fill_prod_frames);
  log_always("");

  log_always("  - XSK Compl stats");
  PRINT_TIME_STAT(xsk_compl_duration);
  PRINT_NUM_STAT(xsk_compl_empty_ring);
  PRINT_NUM_STAT(xsk_compl_invalid_frame);
  PRINT_NUM_STAT(xsk_compl_cons_frames);
  log_always("");

  log_always("  - XSK RX stats");
  PRINT_TIME_STAT(xsk_rx_duration);
  PRINT_NUM_STAT(xsk_rx_empty_ring);
  PRINT_NUM_STAT(xsk_rx_full_pktq);
  PRINT_NUM_STAT(xsk_rx_invalid_frame);
  PRINT_NUM_STAT(xsk_rx_recv_frame);
  log_always("");

  log_always("  - pktbpool stats");
  PRINT_TIME_STAT(pktbpool_alloc_duration);
  PRINT_TIME_STAT(pktbpool_alloc_fill_duration);
  PRINT_NUM_STAT(pktbpool_alloc_too_large);
  PRINT_NUM_STAT(pktbpool_alloc_fill_count);
  PRINT_NUM_STAT(pktbpool_alloc_nofill_count);
  PRINT_NUM_STAT(pktbpool_free_null);
  PRINT_NUM_STAT(pktbpool_free_pbuf);
  log_always("");

  log_always("  - XSK Tick stats");
  PRINT_TIME_STAT(xsk_tick_duration);
  log_always("");

  log_always("  - Stack RX stats");
  PRINT_TIME_STAT(stack_single_process_duration);
  PRINT_TIME_STAT(stack_batch_process_duration);
  PRINT_NUM_STAT(stack_failed_process);
  PRINT_NUM_STAT(stack_no_pkts);
  log_always("");

  log_always("  - Total rx time");
  PRINT_TIME_STAT(pkt_avg_process_duration);
  log_always("");

  log_always("  - Ethernet input stats");
  PRINT_TIME_STAT(ethernet_input_duration);
  PRINT_NUM_STAT(ether_input_too_short);
  PRINT_NUM_STAT(ether_input_remove_header_failed);
  PRINT_NUM_STAT(ether_input_ip_packets);
  PRINT_NUM_STAT(ether_input_arp_packets);
  log_always("");

  log_always("  - Sockets input stats");
  PRINT_NUM_STAT(pktq_enqueue_drop);
  PRINT_NUM_STAT(sockets_udp_callback_recv_pbuf);
  log_always("");

  print_lock_stats(stat);
  RAKIS_SUNLOCK(&write_lock, NULL);
}

#endif
