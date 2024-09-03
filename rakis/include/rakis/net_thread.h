#ifndef RAKIS_NET_THREAD_H
#define RAKIS_NET_THREAD_H
#include "rakis/rakis.h"
#include "rakis/xsk.h"

extern struct libos_thread** g_rakis_net_threads;
noreturn int rakis_net_thread_main(u16 rakis_thread_id, struct libos_thread* this_thread, struct rakis_xsk** xsks, u32 num_xsks);
#endif
