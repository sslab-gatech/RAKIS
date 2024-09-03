#ifndef RAKIS_RING_H
#define RAKIS_RING_H
#include "rakis/common.h"

#if defined(RAKIS_VERIFICATION) && defined(RAKIS_SYMBOLIC)
#include <assert.h>
#include "klee/klee.h"

#define RAKIS_CREATE_RING_STRUCT(__PC) \
  struct rakis_ring_##__PC{ \
    u32 mask; \
    u32 size; \
    u32 entry_size; \
    u32 cached_prod; \
    u32 cached_cons; \
    u32 *producer; \
    u32 *consumer; \
    void *ring; \
    u32   static_mask; \
    u32   static_size; \
    u32   static_entry_size; \
    u32*  static_producer; \
    u32*  static_consumer; \
    void* static_ring; \
  };

RAKIS_CREATE_RING_STRUCT(prod);
RAKIS_CREATE_RING_STRUCT(cons);

static inline void rakis_fv_verify_prod_ring(struct rakis_ring_prod* r){
  // TODO: add checks for verifying wrapping once
  // we integrate integer overflow checks
  klee_assert(r->cached_cons >= r->cached_prod);
  klee_assert((r->cached_cons - r->cached_prod) <= r->size);
  klee_assert(r->mask == r->static_mask);
  klee_assert(r->size == r->static_size);
  klee_assert(r->entry_size == r->static_entry_size);
  klee_assert(r->producer == r->static_producer);
  klee_assert(r->consumer == r->static_consumer);
  klee_assert(r->ring == r->static_ring);
}

static inline void rakis_fv_sym_prod_ring(struct rakis_ring_prod* r){
  *r->producer = klee_int("prod_prod");
  *r->consumer = klee_int("prod_cons");
}

static inline void rakis_fv_sym_cons_ring(struct rakis_ring_cons* r){
  *r->producer = klee_int("cons_prod");
  *r->consumer = klee_int("cons_cons");
}

static inline void rakis_fv_verify_cons_ring(struct rakis_ring_cons* r){
  // TODO: add checks for verifying wrapping once
  // we integrate integer overflow checks
  klee_assert(r->cached_prod >= r->cached_cons);
  klee_assert((r->cached_prod - r->cached_cons) <= r->size);
  klee_assert(r->mask == r->static_mask);
  klee_assert(r->size == r->static_size);
  klee_assert(r->entry_size == r->static_entry_size);
  klee_assert(r->producer == r->static_producer);
  klee_assert(r->consumer == r->static_consumer);
  klee_assert(r->ring == r->static_ring);
}

#define RAKIS_CREATE_RING_IDX_VERIFIER(__PC) \
  static inline void rakis_fv_verify_##__PC##_ring_idx(struct rakis_ring_##__PC* ring, u32 idx, void* elem_addr){ \
    u32 masked_idx = idx & ring->static_mask; \
    klee_assert(masked_idx >= 0 && masked_idx < ring->static_size); \
    void* slot = ring->static_ring + masked_idx * ring->static_entry_size; \
    void* ring_end = ring->static_ring + ring->static_size * ring->static_entry_size; \
    klee_assert(slot >= ring->static_ring && (slot + ring->static_entry_size) <= ring_end); \
    klee_assert(elem_addr == slot); \
  }

RAKIS_CREATE_RING_IDX_VERIFIER(prod);
RAKIS_CREATE_RING_IDX_VERIFIER(cons);

#else
#define RAKIS_CREATE_RING_STRUCT(__PC) \
  struct rakis_ring_##__PC{ \
    u32 mask; \
    u32 size; \
    u32 entry_size; \
    u32 cached_prod; \
    u32 cached_cons; \
    u32 *producer; \
    u32 *consumer; \
    void *ring; \
  };

RAKIS_CREATE_RING_STRUCT(prod);
RAKIS_CREATE_RING_STRUCT(cons);

#define rakis_fv_verify_prod_ring(r);
#define rakis_fv_verify_cons_ring(r);
#define rakis_fv_verify_prod_ring_idx(r, idx, elem_addr);
#define rakis_fv_verify_cons_ring_idx(r, idx, elem_addr);
#define rakis_fv_sym_prod_ring(r)
#define rakis_fv_sym_cons_ring(r)
#endif

RAKIS_INLINE
bool validate_ring_values(u32 prod, u32 cons, u32 size){
  if(prod >= cons){
    // normal case when producer is ahead of consumer
    return (prod - cons) <= size;
  }

  // otherwise, it must have wrapped

  // should it wrap?
  // the cons must be more than size behind the max for it to wrap
  u32 distance_to_wrap = UINT32_MAX - cons;
  if(distance_to_wrap >= size){
    // it should be enough without wrapping
    // this is invalid
    return false;
  }

  // otherwise, it should wrap
  // but prod (+1 because indexing starts at 0) + distance_to_wrap 
  // should be less than or equal size
  return ((prod + 1 + distance_to_wrap) <= size);
}

RAKIS_INLINE
void init_rakis_ring_prod(struct rakis_ring_prod* rakis_ring_prod,
    u32 size, u32 entry_size, u32* producer, u32* consumer, void* ring){
  rakis_ring_prod->mask = size - 1;
  rakis_ring_prod->size = size;
  rakis_ring_prod->entry_size = entry_size;
  rakis_ring_prod->producer = producer;
  rakis_ring_prod->consumer = consumer;
  rakis_ring_prod->ring = ring;
  rakis_ring_prod->cached_prod = 0;
  rakis_ring_prod->cached_cons = size;

#if defined(RAKIS_VERIFICATION) && defined(RAKIS_SYMBOLIC)
  rakis_ring_prod->static_mask = size - 1;
  rakis_ring_prod->static_size = size;
  rakis_ring_prod->static_entry_size = entry_size;
  rakis_ring_prod->static_producer = producer;
  rakis_ring_prod->static_consumer = consumer;
  rakis_ring_prod->static_ring = ring;
#endif
}

RAKIS_INLINE
void* rakis_ring_prod_get_elem(struct rakis_ring_prod *r, u32 idx){
  rakis_fv_verify_prod_ring(r);
  void* elem_addr = r->ring + (idx & r->mask) * r->entry_size;
  rakis_fv_verify_prod_ring_idx(r, idx, elem_addr);
  return elem_addr;
}

RAKIS_INLINE
u32 rakis_ring_prod_free_num(struct rakis_ring_prod *r, u32 num){
  rakis_fv_verify_prod_ring(r);
  u32 free_entries = r->cached_cons - r->cached_prod;

  if (free_entries >= num)
    return free_entries;

  u32 temp_cons = __atomic_load_n(r->consumer, __ATOMIC_ACQUIRE);
  if (!validate_ring_values(r->cached_prod, temp_cons, r->size)) {
    rakis_fv_verify_prod_ring(r);
    return 0;
  }

  r->cached_cons = temp_cons + r->size;
  rakis_fv_verify_prod_ring(r);
  return r->cached_cons - r->cached_prod;
}

RAKIS_INLINE
u32 rakis_ring_prod_reserve(struct rakis_ring_prod *prod, u32 nb, u32 *idx){
  rakis_fv_verify_prod_ring(prod);
  *idx = prod->cached_prod;
  prod->cached_prod += nb;
  rakis_fv_verify_prod_ring(prod);
  return nb;
}

RAKIS_INLINE void rakis_ring_prod_submit(struct rakis_ring_prod *prod){
  rakis_fv_verify_prod_ring(prod);
  __atomic_store_n(prod->producer, prod->cached_prod, __ATOMIC_RELEASE);
}

RAKIS_INLINE
void init_rakis_ring_cons(struct rakis_ring_cons* rakis_ring_cons,
    u32 size, u32 entry_size, u32* producer, u32* consumer, void* ring){
  rakis_ring_cons->mask = size - 1;
  rakis_ring_cons->size = size;
  rakis_ring_cons->entry_size = entry_size;
  rakis_ring_cons->producer = producer;
  rakis_ring_cons->consumer = consumer;
  rakis_ring_cons->ring = ring;
  rakis_ring_cons->cached_prod = 0;
  rakis_ring_cons->cached_cons = 0;

#if defined(RAKIS_VERIFICATION) && defined(RAKIS_SYMBOLIC)
  rakis_ring_cons->static_mask = size - 1;
  rakis_ring_cons->static_size = size;
  rakis_ring_cons->static_entry_size = entry_size;
  rakis_ring_cons->static_producer = producer;
  rakis_ring_cons->static_consumer = consumer;
  rakis_ring_cons->static_ring = ring;
#endif
}

RAKIS_INLINE
void* rakis_ring_cons_get_elem(struct rakis_ring_cons *r, u32 idx){
  rakis_fv_verify_cons_ring(r);
  void* elem_addr = r->ring + (idx & r->mask) * r->entry_size;
  rakis_fv_verify_cons_ring_idx(r, idx, elem_addr);
  return elem_addr;
}

RAKIS_INLINE u32 rakis_ring_cons_avail_num(struct rakis_ring_cons *r){
  rakis_fv_verify_cons_ring(r);
  u32 entries = r->cached_prod - r->cached_cons;

  if (entries == 0) {
    u32 temp_prod = __atomic_load_n(r->producer, __ATOMIC_ACQUIRE);
    if(!validate_ring_values(temp_prod, r->cached_cons, r->size)){
      rakis_fv_verify_cons_ring(r);
      return 0;
    }

    r->cached_prod = temp_prod;
    entries = r->cached_prod - r->cached_cons;
  }

  rakis_fv_verify_cons_ring(r);
  return entries;
}

RAKIS_INLINE
u32 rakis_ring_cons_peek(struct rakis_ring_cons *cons, u32 nb, u32 *idx){
  rakis_fv_verify_cons_ring(cons);
  *idx = cons->cached_cons;
  cons->cached_cons += nb;
  rakis_fv_verify_cons_ring(cons);
  return nb;
}

RAKIS_INLINE
void rakis_ring_cons_release(struct rakis_ring_cons *cons){
  rakis_fv_verify_cons_ring(cons);
  __atomic_store_n(cons->consumer, cons->cached_cons, __ATOMIC_RELEASE);
  rakis_fv_verify_cons_ring(cons);
}

#endif
