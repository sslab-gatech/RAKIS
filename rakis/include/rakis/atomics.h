#ifndef RAKIS_ATOMICS_H
#define RAKIS_ATOMICS_H

#define RAKIS_GET_ATOMIC(VAR) (__atomic_load_n(VAR, __ATOMIC_ACQUIRE))
#define RAKIS_SET_ATOMIC(VAR, VALUE) (__atomic_store_n(VAR, VALUE, __ATOMIC_RELEASE))
#define RAKIS_DEC_ATOMIC(VAR) (__atomic_sub_fetch(VAR, 1, __ATOMIC_RELEASE))
#define RAKIS_INC_ATOMIC(VAR) (__atomic_add_fetch(VAR, 1, __ATOMIC_RELEASE))
#define RAKIS_IS_ATOMIC_EQ(VAR, VALUE) (RAKIS_GET_ATOMIC(VAR) == VALUE)
#define RAKIS_WAIT_UNTIL_ATOMIC_EQ(VAR, VALUE) \
  while (!RAKIS_IS_ATOMIC_EQ(VAR, VALUE)) { \
    CPU_RELAX();\
  }
#define RAKIS_EXCHANGE_ATOMIC(VAR, VALUE) (__atomic_exchange_n(VAR, VALUE, __ATOMIC_RELEASE))
#define RAKIS_CMPEXCH_ATOMIC(VAR, OLD, NEW) (__atomic_compare_exchange_n(VAR, OLD, NEW, false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE))
#define RAKIS_OR_ATOMIC(VAR, VALUE) (__atomic_or_fetch(VAR, VALUE, __ATOMIC_RELEASE))
#define RAKIS_AND_ATOMIC(VAR, VALUE) (__atomic_and_fetch(VAR, VALUE, __ATOMIC_RELEASE))
#define RAKIS_ADD_ATOMIC(VAR, VALUE) (__atomic_add_fetch(VAR, VALUE, __ATOMIC_RELEASE))
#define RAKIS_SUB_ATOMIC(VAR, VALUE) (__atomic_sub_fetch(VAR, VALUE, __ATOMIC_RELEASE))
#endif
