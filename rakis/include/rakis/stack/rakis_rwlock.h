#ifndef RAKIS_RWLOCK_H
#define RAKIS_RWLOCK_H
#include <stdbool.h>

// this is just a wrapper around an implementation of a lock.
// In this case we use libos_rwlock.h

struct rakis_rwlock {
  struct libos_rwlock* lock;
};

#ifdef RAKIS_FUZZ
// fuzzing is single threaded, so we don't need to use locks
#define rakis_rwlock_create(x) 0
#define rakis_rwlock_destroy(x)
#define rakis_rwlock_read_lock(x)
#define rakis_rwlock_read_unlock(x)
#define rakis_rwlock_write_lock(x)
#define rakis_rwlock_write_unlock(x)
#else
int rakis_rwlock_create(struct rakis_rwlock* l);
void rakis_rwlock_destroy(struct rakis_rwlock* l);
void rakis_rwlock_read_lock(struct rakis_rwlock* l);
void rakis_rwlock_read_unlock(struct rakis_rwlock* l);
void rakis_rwlock_write_lock(struct rakis_rwlock* l);
void rakis_rwlock_write_unlock(struct rakis_rwlock* l);
#endif

#endif
