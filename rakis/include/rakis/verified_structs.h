#include "rakis/rakis.h"
#include "rakis/linux_io_uring.h"

// kernel structs for verification of shared memory layouts of io_uring and XDP
// the following is for linux kernel 6.2
// (rakis) TODO: split this into a separate header file for each kernel version

#define ____cacheline_aligned __attribute__((__aligned__(RAKIS_CACHELINE_SIZE)))
struct xdp_ring {
	u32 producer ____cacheline_aligned;
	u32 pad1 ____cacheline_aligned;
	u32 consumer ____cacheline_aligned;
	u32 pad2 ____cacheline_aligned;
	u32 flags;
	u32 pad3 ____cacheline_aligned;
	void* ring ____cacheline_aligned;
};

struct io_uring {
	u32 head ____cacheline_aligned;
	u32 tail ____cacheline_aligned;
};

typedef struct {
        int counter;
} atomic_t;

struct io_rings {
	struct io_uring		sq, cq;
	u32			sq_ring_mask, cq_ring_mask;
	u32			sq_ring_entries, cq_ring_entries;
	u32			sq_dropped;
	atomic_t		sq_flags;
	u32			cq_flags;
	u32			cq_overflow;
	struct io_uring_cqe	cqes[] ____cacheline_aligned;
};
