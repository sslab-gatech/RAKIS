#ifndef RAKIS_XSK_MANAGER_H
#define RAKIS_XSK_MANAGER_H
#include "rakis/netif.h"
#include "rakis/pal.h"
#include "rakis/pktq.h"
#include "rakis/rakis.h"
#include "rakis/rakis_ring.h"
#include "rakis/stack/rakis_spinlock.h"

// This is defined in linux/bpf.h
#define XDP_PACKET_HEADROOM 256

struct rakis_xsk;

#ifdef RAKIS_VERIFICATION
// we need access to xsk_fd in this compilation to use it in the sendto syscall
int rakis_xsk_get_fd(struct rakis_xsk* xsk);

#ifdef RAKIS_SYMBOLIC
// we need access to the rings to verify them after symbolic execution
#define RAKIS_XSK_CREATE_RING_GETTER_DEF(__PC, __R) \
  struct rakis_ring_##__PC* rakis_xsk_get_##__PC##_##__R##_ring(struct rakis_xsk* xsk);

RAKIS_XSK_CREATE_RING_GETTER_DEF(prod, fill);
RAKIS_XSK_CREATE_RING_GETTER_DEF(cons, compl);
RAKIS_XSK_CREATE_RING_GETTER_DEF(prod, tx);
RAKIS_XSK_CREATE_RING_GETTER_DEF(cons, rx);
#endif
#endif

void* rakis_xsk_get_pktq(struct rakis_xsk* xsk);
void* rakis_xsk_get_lwip(struct rakis_xsk* xsk);
struct rakis_xsk* rakis_xsk_get_xsk(struct rakis_xsk* xsks, int n);
struct rakis_xsk* rakis_xsk_alloc_xsks(int n);
int rakis_new_xsk(
    struct rakis_xsk_cfg* xsk_cfg,
    struct rakis_xsk_pal* xsk_pal,
    struct rakis_netif* rakis_netif,
    struct rakis_xsk* xsk);
void rakis_xsk_tick(struct rakis_xsk* xsk);
u32 rakis_xsk_send(struct rakis_xsk* xsk, struct pbuf* p);
#endif
