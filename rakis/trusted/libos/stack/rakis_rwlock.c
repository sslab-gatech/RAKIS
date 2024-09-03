#include "rakis/stack/rakis_rwlock.h"
#include "libos_rwlock.h"

int rakis_rwlock_create(struct rakis_rwlock* l){
  l->lock = calloc(1, sizeof(struct libos_rwlock));
  if(!l->lock){
    return -1;
  }

  return rwlock_create(l->lock) ? 0 : -1;
}

void rakis_rwlock_destroy(struct rakis_rwlock* l){
  rwlock_destroy(l->lock);
  free(l->lock);
  l->lock = NULL;
}

void rakis_rwlock_read_lock(struct rakis_rwlock* l){
  rwlock_read_lock(l->lock);
}

void rakis_rwlock_read_unlock(struct rakis_rwlock* l){
  rwlock_read_unlock(l->lock);
}

void rakis_rwlock_write_lock(struct rakis_rwlock* l){
  rwlock_write_lock(l->lock);
}

void rakis_rwlock_write_unlock(struct rakis_rwlock* l){
  rwlock_write_unlock(l->lock);
}
