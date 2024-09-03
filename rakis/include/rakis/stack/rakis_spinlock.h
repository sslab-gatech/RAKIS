#ifndef RAKIS_SPINLOCK_H
#define RAKIS_SPINLOCK_H
#include <stdbool.h>
#include <stdint.h>

#if defined(RAKIS_VERIFICATION) || defined (RAKIS_FUZZ)
#define CPU_RELAX()
#else
#include "cpu.h"
#endif
#include "rakis/stack/rakis_misc.h"

// copied from spinlock.h to avoid build conflicts
// TODO: remove this once we have a better solution

struct rakis_spinlock{
    uint32_t lock;
};

#define SPINLOCK_UNLOCKED            0
#define SPINLOCK_LOCKED              1

#define INIT_SPINLOCK_UNLOCKED { .lock = SPINLOCK_UNLOCKED }

#ifdef RAKIS_STAT
#define RAKIS_SLOCK(l, s) rakis_spinlock_lock(l, s)
#define RAKIS_STRYLOCK(l, s) rakis_spinlock_trylock(l, s)
#define RAKIS_SUNLOCK(l, s) rakis_spinlock_unlock(l, s)
#else
#define RAKIS_SLOCK(l, s) rakis_spinlock_lock(l, NULL)
#define RAKIS_STRYLOCK(l, s) rakis_spinlock_trylock(l, NULL)
#define RAKIS_SUNLOCK(l, s) rakis_spinlock_unlock(l, NULL)
#endif

static inline void rakis_spinlock_init(struct rakis_spinlock* lock) {
    __atomic_store_n(&lock->lock, SPINLOCK_UNLOCKED, __ATOMIC_RELAXED);
}

static inline void rakis_spinlock_lock(struct rakis_spinlock* lock, struct rakis_lock_stat* lock_stat) {
    uint32_t val;
    RAKIS_LOCK_STAT_INC(lock_stat, tot_lock_attempts);

    if (__atomic_exchange_n(&lock->lock, SPINLOCK_LOCKED, __ATOMIC_ACQUIRE) == SPINLOCK_UNLOCKED) {
        RAKIS_LOCK_STAT_INC(lock_stat, succ_lock_attempts);
        RAKIS_LOCK_STAT_DURATION_START(lock_stat, hold_time);
        return;
    }

    RAKIS_LOCK_STAT_DURATION_START(lock_stat, wait_time);
    RAKIS_LOCK_STAT_INC(lock_stat, fail_lock_attempts);

    do {
        while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED) != SPINLOCK_UNLOCKED)
            CPU_RELAX();
        val = SPINLOCK_UNLOCKED;
    } while (!__atomic_compare_exchange_n(&lock->lock, &val, SPINLOCK_LOCKED, /*weak=*/false,
                                          __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));

    RAKIS_LOCK_STAT_DURATION_END(lock_stat, wait_time);
    RAKIS_LOCK_STAT_DURATION_START(lock_stat, hold_time);
}

static inline bool rakis_spinlock_trylock(struct rakis_spinlock* lock, struct rakis_lock_stat* lock_stat) {
    RAKIS_LOCK_STAT_INC(lock_stat, tot_lock_attempts);

    if (__atomic_exchange_n(&lock->lock, SPINLOCK_LOCKED, __ATOMIC_ACQUIRE) == SPINLOCK_UNLOCKED) {
      RAKIS_LOCK_STAT_DURATION_START(lock_stat, hold_time);
      RAKIS_LOCK_STAT_INC(lock_stat, succ_lock_attempts);
      return true;
    }

    RAKIS_LOCK_STAT_INC(lock_stat, fail_lock_attempts);
    return false;
}

/*!
 * \brief Release spinlock.
 */
static inline void rakis_spinlock_unlock(struct rakis_spinlock* lock, struct rakis_lock_stat* lock_stat) {
    RAKIS_LOCK_STAT_DURATION_END(lock_stat, hold_time);
    __atomic_store_n(&lock->lock, SPINLOCK_UNLOCKED, __ATOMIC_RELEASE);
}

#endif
