#include "rakis/io_uring.h"
#include "rakis/linux_io_uring.h"
#include "rakis/pal.h"
#include "rakis/rakis.h"
#include <errno.h>

#ifdef RAKIS_VERIFICATION
#include "rakis/fv/host.h"
#include <sys/syscall.h>
#else
#include "pal.h"
#include "pal_linux.h"
#endif

#define RAKIS_CHECK_STOP_WAITING(wakeup)  ((wakeup) ? RAKIS_GET_ATOMIC(wakeup) : false)

#define RAKIS_IO_URING_CQEREF_META_OFFSET      UINT16_MAX
#define RAKIS_IO_URING_CQEREF_META_TIMER           1
#define RAKIS_IO_URING_CQEREF_META_POLL_REMOVE     2
#define RAKIS_IO_URING_CQEREF_USERDATA(user_data_base, i) ((user_data_base) + (i))
#define RAKIS_IO_URING_CQEREF_INDEX(user_data_base, raw_user_data) ((raw_user_data) - (user_data_base))
#define RAKIS_IO_URING_CQEREF_GET_META_TIMER(user_data_base) \
  ((user_data_base) + RAKIS_IO_URING_CQEREF_META_OFFSET + RAKIS_IO_URING_CQEREF_META_TIMER)
#define RAKIS_IO_URING_CQEREF_IS_META_TIMER(user_data_base, raw_user_data) \
  ((raw_user_data) == RAKIS_IO_URING_CQEREF_GET_META_TIMER(user_data_base))
#define RAKIS_IO_URING_CQEREF_GET_META_POLL_REMOVE(user_data_base) \
  ((user_data_base) + RAKIS_IO_URING_CQEREF_META_OFFSET + RAKIS_IO_URING_CQEREF_META_POLL_REMOVE)
#define RAKIS_IO_URING_CQEREF_IS_META_POLL_REMOVE(user_data_base, raw_user_data) \
  ((raw_user_data) == RAKIS_IO_URING_CQEREF_GET_META_POLL_REMOVE(user_data_base))
#define RAKIS_IO_URING_IS_VALID_CQEREF(user_data_base, raw_user_data, nfds) \
  (\
    (((raw_user_data) >= (user_data_base)) && ((raw_user_data) < (user_data_base) + (nfds))) || \
    RAKIS_IO_URING_CQEREF_IS_META_TIMER(user_data_base, raw_user_data) || \
    RAKIS_IO_URING_CQEREF_IS_META_POLL_REMOVE(user_data_base, raw_user_data) \
   )

struct rakis_io_uring{
  int fd;
  bool is_used;

  struct rakis_ring_prod sqring;
  struct rakis_ring_cons cqring;
};

RAKIS_INLINE
struct rakis_io_uring* allocate_io_uring(void){/*{{{*/
#ifdef RAKIS_VERIFICATION
  struct rakis_io_uring_pool* rakis_io_uring_pool = &g_rakis_io_uring_pool;
#else
  struct pal_public_state* pal_state = PalGetPalPublicState();
  if (!pal_state) {
    return NULL;
  }

  struct rakis_io_uring_pool* rakis_io_uring_pool = &pal_state->rakis_io_uring_pool;
#endif

  for (u32 i =0; i < rakis_io_uring_pool->size; i++) {
    struct rakis_io_uring* rakis_io_uring = &rakis_io_uring_pool->rakis_io_urings[i];
    bool f = false;
    if(RAKIS_CMPEXCH_ATOMIC(&rakis_io_uring->is_used, &f, true))
      return rakis_io_uring;
  }

  return NULL;
}/*}}}*/

RAKIS_INLINE
struct rakis_io_uring* get_rakis_io_uring(void){/*{{{*/
  struct rakis_io_uring** rakis_io_uring_ptr;

#ifdef RAKIS_SGX_HOST
  struct pal_handle_thread* thread_handle = GET_ENCLAVE_TCB(thread);
  if (!thread_handle) {
    return NULL;
  }

  rakis_io_uring_ptr = &thread_handle->rakis_io_uring;
#else

#ifdef RAKIS_VERIFICATION
  rakis_io_uring_ptr = &g_rakis_io_uring;

#else
  PAL_LINUX_TCB* tcb = pal_get_linux_tcb();
  if (!tcb) {
    return NULL;
  }

  rakis_io_uring_ptr = &tcb->rakis_io_uring;
#endif
#endif

  if (*rakis_io_uring_ptr) {
    return *rakis_io_uring_ptr;
  }

  // we need to allocate a new gior
  *rakis_io_uring_ptr = allocate_io_uring();
  return *rakis_io_uring_ptr;
}/*}}}*/

RAKIS_INLINE
struct io_uring_sqe* io_uring_prep_sqe_rw(struct io_uring_sqe* sqe,/*{{{*/
    u8 opcode,
    int fd,
    const void* buf,
    size_t count,
    long offset,
    u64 user_data){

  WRITE_ONCE(sqe->opcode, opcode);
  WRITE_ONCE(sqe->flags, 0);
  WRITE_ONCE(sqe->ioprio, 0);
  WRITE_ONCE(sqe->fd, fd);
  WRITE_ONCE(sqe->len, count);
  WRITE_ONCE(sqe->addr, (unsigned long)buf);
  WRITE_ONCE(sqe->off, offset);
  WRITE_ONCE(sqe->user_data, user_data);
  return sqe;
}/*}}}*/

RAKIS_INLINE
struct io_uring_sqe* io_uring_prep_sqe_sr(struct io_uring_sqe* sqe,/*{{{*/
    u8 opcode,
    int fd,
    struct msghdr* msghdr,
    u64 user_data){

  sqe->opcode = opcode;
  sqe->flags = 0;
  sqe->ioprio = 0;
  sqe->fd = fd;
  sqe->len = sizeof(struct msghdr);
  sqe->addr = (unsigned long)msghdr;
  sqe->user_data = user_data;
  return sqe;
}/*}}}*/

RAKIS_INLINE
struct io_uring_cqe* io_uring_get_cqe(struct rakis_ring_cons* cq, u32 idx){/*{{{*/
  return rakis_ring_cons_get_elem(cq, idx);
}/*}}}*/

RAKIS_INLINE
struct io_uring_sqe* io_uring_get_sqe(struct rakis_ring_prod* sq, u32 idx){/*{{{*/
  struct io_uring_sqe* sqe = rakis_ring_prod_get_elem(sq, idx);

#ifndef RAKIS_SYMBOLIC
  // when exeucting symbolicly, dont overwrite the symbolic values in the sqe
  // so that they are explored
  memset(sqe, 0, sizeof(struct io_uring_sqe));
#endif

  return sqe;
}/*}}}*/

RAKIS_INLINE
long io_uring_wait_for_sqes(struct rakis_ring_prod* sq, bool* wakeup, u32 num){/*{{{*/
  while(rakis_ring_prod_free_num(sq, num) < num){
    if(RAKIS_CHECK_STOP_WAITING(wakeup)){
      return -1;
    }
  }

  u32 idx = 0;
  rakis_ring_prod_reserve(sq, num, &idx);
  return idx;
}/*}}}*/

RAKIS_INLINE
struct io_uring_sqe* io_uring_wait_for_sqe(struct rakis_ring_prod* sq, bool* wakeup){/*{{{*/
  long idx = io_uring_wait_for_sqes(sq, wakeup, 1);
  if(idx == -1){
    return NULL;
  }
  return io_uring_get_sqe(sq, idx);
}/*}}}*/

RAKIS_INLINE
int io_uring_wait_for_any_cqe(struct rakis_ring_cons* cq, bool* wakeup, u32 *idx){/*{{{*/
  int num = 0;
  do{
    if(RAKIS_CHECK_STOP_WAITING(wakeup)){
      return -1;
    }
    num  = rakis_ring_cons_avail_num(cq);
  } while(num == 0);

  rakis_ring_cons_peek(cq, num, idx);
  return num;
}/*}}}*/

RAKIS_INLINE
size_t io_uring_wait_for_exact_cqe(struct rakis_ring_cons* cq, u64 user_data){/*{{{*/
  while(true){
    u32 cons_avail = rakis_ring_cons_avail_num(cq);
    if(cons_avail == 0){

#ifdef RAKIS_SYMBOLIC
    // with symbolic execution, we need to make sure that we dont get stuck
    // as there is always a symbolic path that will not find the cqe
    return -EIO;
#else
      continue;
#endif

    }

    u32 idx = 0;
    int ret = 0;
    bool found = false;
    rakis_ring_cons_peek(cq, cons_avail, &idx);

    for(u32 i = 0; i < cons_avail; i++){
      struct io_uring_cqe* cqe = io_uring_get_cqe(cq, idx++);
      u64 tmp_user_data = READ_ONCE(cqe->user_data);
      if(tmp_user_data == user_data){
        ret = READ_ONCE(cqe->res);
        found = true;
        break;
      }
    }

    rakis_ring_cons_release(cq);

    if(found){
      return ret;
    }

#ifdef RAKIS_SYMBOLIC
    // with symbolic execution, we need to make sure that we dont get stuck
    // as there is always a symbolic path that will not find the cqe
    return -EIO;
#endif
  }
}/*}}}*/

RAKIS_INLINE
int rakis_init_pal_io_uring(struct rakis_io_uring_cfg* io_uring_cfg,/*{{{*/
    struct rakis_io_uring_pal* rakis_io_uring_pal,
    struct rakis_io_uring* rakis_io_uring){

  rakis_io_uring->fd = rakis_io_uring_pal->fd;
  rakis_io_uring->is_used = false;

  struct rakis_io_uring_sqring_pal* sqring_u = &rakis_io_uring_pal->sqring;
  init_rakis_ring_prod(&rakis_io_uring->sqring,
      io_uring_cfg->entries_num,
      sizeof(struct io_uring_sqe),
      sqring_u->producer,
      sqring_u->consumer,
      sqring_u->sqes);

  struct rakis_io_uring_cqring_pal* cqring_u = &rakis_io_uring_pal->cqring;
  init_rakis_ring_cons(&rakis_io_uring->cqring,
      io_uring_cfg->entries_num * 2,
      sizeof(struct io_uring_cqe),
      cqring_u->producer,
      cqring_u->consumer,
      cqring_u->cqes);

  return 0;
}/*}}}*/

RAKIS_INLINE
long io_uring_poll_start(struct rakis_ring_prod* sq,/*{{{*/
    struct pollfd* fds, size_t nfds, size_t needed_sqes, struct __kernel_timespec* timeout_us, bool* wakeup){
  u32 idx;
  u64 user_data_base = 0;

  long idxs = io_uring_wait_for_sqes(sq, wakeup, needed_sqes);
  if(idxs == -1){
    // this means we were woken up
    return -1;
  }

  user_data_base = idxs;
  idx = idxs;
  for (u32 i = 0; i < nfds; i++) {
    if (fds[i].fd < 0) {
      continue;
    }

    struct io_uring_sqe* sqe = io_uring_get_sqe(sq, idx++);
    u64 user_data = RAKIS_IO_URING_CQEREF_USERDATA(user_data_base, i);

    WRITE_ONCE(sqe->opcode, IORING_OP_POLL_ADD);
    WRITE_ONCE(sqe->fd, fds[i].fd);
    WRITE_ONCE(sqe->poll_events, fds[i].events);
    WRITE_ONCE(sqe->user_data, user_data);
  }

  if (timeout_us) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(sq, idx);
    u64 user_data = RAKIS_IO_URING_CQEREF_GET_META_TIMER(user_data_base);

    WRITE_ONCE(sqe->opcode, IORING_OP_TIMEOUT);
    WRITE_ONCE(sqe->fd, -1);
    WRITE_ONCE(sqe->addr, (u64)timeout_us);
    WRITE_ONCE(sqe->len, 1);
    WRITE_ONCE(sqe->off, 1);
    WRITE_ONCE(sqe->timeout_flags, 0);
    WRITE_ONCE(sqe->user_data, user_data);
  }

  rakis_ring_prod_submit(sq);
  return user_data_base;
}/*}}}*/

RAKIS_INLINE
int io_uring_poll_wait(struct rakis_ring_cons* cq, struct pollfd* fds, size_t nfds, u64 user_data_base, bool* wakeup){/*{{{*/
  bool timedout = false;
  int revents = 0;

  while (true){
    u32 idx = 0;
    int cqe_avail = io_uring_wait_for_any_cqe(cq, wakeup, &idx);
    if(cqe_avail == -1){
      // woken up
      return 0;
    }

    for (int i = 0; i < cqe_avail; i++) {
      struct io_uring_cqe* cqe = io_uring_get_cqe(cq, idx++);
      u64 user_data = READ_ONCE(cqe->user_data);

      if (!RAKIS_IO_URING_IS_VALID_CQEREF(user_data_base, user_data, nfds)) {
        continue;
      }

      int res = READ_ONCE(cqe->res);
      if (RAKIS_IO_URING_CQEREF_IS_META_TIMER(user_data_base, user_data)) {
        if (res == -ETIME) {
          timedout = true;
        }
      } else {
        u32 user_data_idx = RAKIS_IO_URING_CQEREF_INDEX(user_data_base, user_data);
        if (res){
          fds[user_data_idx].revents = res;
          revents++;
        }
      }
    }

    rakis_ring_cons_release(cq);

    if (revents) {
      return revents;
    }

    if (timedout) {
      return -ETIME;
    }
  }
}/*}}}*/

RAKIS_INLINE
void io_uring_poll_done(struct rakis_ring_prod* sq,/*{{{*/
    struct pollfd* fds, size_t nfds, size_t needed_sqes, u64 user_data_base, bool remove_timer){
  u32 idx;

  idx = io_uring_wait_for_sqes(sq, NULL, needed_sqes);
  for (u32 i = 0; i < nfds; i++) {
    if (fds[i].fd < 0) {
      continue;
    }

    if (fds[i].revents == 0) {
      struct io_uring_sqe* sqe = io_uring_get_sqe(sq, idx++);
      u64 user_data = RAKIS_IO_URING_CQEREF_USERDATA(user_data_base, i);

      WRITE_ONCE(sqe->opcode, IORING_OP_POLL_REMOVE);
      WRITE_ONCE(sqe->fd, -1);
      WRITE_ONCE(sqe->addr, user_data);
      WRITE_ONCE(sqe->user_data, RAKIS_IO_URING_CQEREF_GET_META_POLL_REMOVE(user_data_base));
    }
  }

  if (remove_timer) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(sq, idx);
    WRITE_ONCE(sqe->opcode, IORING_OP_TIMEOUT_REMOVE);
    WRITE_ONCE(sqe->fd, -1);
    WRITE_ONCE(sqe->addr, RAKIS_IO_URING_CQEREF_GET_META_TIMER(user_data_base));
    WRITE_ONCE(sqe->timeout_flags, 0);
    WRITE_ONCE(sqe->user_data, RAKIS_IO_URING_CQEREF_GET_META_POLL_REMOVE(user_data_base));
  }

  rakis_ring_prod_submit(sq);
}/*}}}*/

int rakis_io_uring_poll(struct pollfd* fds, size_t nfds, struct __kernel_timespec* timeout_us, bool* wakeup){/*{{{*/
  struct rakis_io_uring* rakis_io_uring = get_rakis_io_uring();
  if (!rakis_io_uring) {
    return -EIO;
  }

  size_t needed_sqes = (timeout_us ? 1 : 0);;
  for (u32 i = 0; i < nfds; i++) {
    if (fds[i].fd >= 0) {
      needed_sqes++;
    }
  }

  if(needed_sqes > rakis_io_uring->sqring.size){
    log_error("Not enough io_uring entries for poll");
    log_error("Reverting back to ocall_poll");
    return -EIO;
  }

  long user_data_base = io_uring_poll_start(&rakis_io_uring->sqring, fds, nfds, needed_sqes, timeout_us, wakeup);
  if(user_data_base < 0){
    return 0;
  }

  int poll_ret = io_uring_poll_wait(&rakis_io_uring->cqring, fds, nfds, user_data_base, wakeup);

  if(poll_ret > 0){
    needed_sqes -= poll_ret;
  } else if (poll_ret == -ETIME) {
    needed_sqes--;
  } else if (poll_ret == -1) {
    poll_ret = 0;
  }

  io_uring_poll_done(&rakis_io_uring->sqring,
      fds,
      nfds,
      needed_sqes,
      user_data_base,
      timeout_us != NULL && poll_ret != -ETIME);

  return poll_ret;
}/*}}}*/

int rakis_io_uring_recv(int fd, struct msghdr* msghdr){/*{{{*/
  struct rakis_io_uring* rakis_io_uring = get_rakis_io_uring();
  if (!rakis_io_uring) {
    return -EIO;
  }

  struct io_uring_sqe* sqe = io_uring_wait_for_sqe(&rakis_io_uring->sqring, NULL);
  if (!sqe) {
    return -EIO;
  }

  u64 user_data = (u64)msghdr;
  io_uring_prep_sqe_sr(sqe, IORING_OP_RECVMSG, fd, msghdr, user_data);
  rakis_ring_prod_submit(&rakis_io_uring->sqring);

  return io_uring_wait_for_exact_cqe(&rakis_io_uring->cqring, user_data);
}/*}}}*/

int rakis_io_uring_send(int fd, struct msghdr* msghdr){/*{{{*/
  struct rakis_io_uring* rakis_io_uring = get_rakis_io_uring();
  if (!rakis_io_uring) {
    return -EIO;
  }

  struct io_uring_sqe* sqe = io_uring_wait_for_sqe(&rakis_io_uring->sqring, NULL);
  if (!sqe) {
    return -EIO;
  }

  u64 user_data = (u64)msghdr;
  io_uring_prep_sqe_sr(sqe, IORING_OP_SENDMSG, fd, msghdr, user_data);
  rakis_ring_prod_submit(&rakis_io_uring->sqring);

  return io_uring_wait_for_exact_cqe(&rakis_io_uring->cqring, user_data);
}/*}}}*/

int rakis_io_uring_read(int fd, void* buf, size_t count, long offset){/*{{{*/
  struct rakis_io_uring* rakis_io_uring = get_rakis_io_uring();
  if (!rakis_io_uring) {
    return -EIO;
  }

  rakis_fv_sym_prod_ring(&rakis_io_uring->sqring);
  rakis_fv_sym_cons_ring(&rakis_io_uring->cqring);

  struct io_uring_sqe* sqe = io_uring_wait_for_sqe(&rakis_io_uring->sqring, NULL);
  if (!sqe) {
    return -EIO;
  }

  u64 user_data = (u64)buf;
  io_uring_prep_sqe_rw(sqe, IORING_OP_READ, fd, buf, count, offset, user_data);
  rakis_ring_prod_submit(&rakis_io_uring->sqring);

#if defined(RAKIS_VERIFICATION) && !defined(RAKIS_SYMBOLIC)
  // we need the nudge as there is no monitor to do it for us
  syscall(SYS_io_uring_enter, rakis_io_uring->fd, 1, 1, 0, 0);
#endif

  return io_uring_wait_for_exact_cqe(&rakis_io_uring->cqring, user_data);
}/*}}}*/

int rakis_io_uring_write(int fd, const void* buf, size_t count, long offset){/*{{{*/
  struct rakis_io_uring* rakis_io_uring = get_rakis_io_uring();
  if (!rakis_io_uring) {
    return -EIO;
  }

  rakis_fv_sym_prod_ring(&rakis_io_uring->sqring);
  rakis_fv_sym_cons_ring(&rakis_io_uring->cqring);

  struct io_uring_sqe* sqe = io_uring_wait_for_sqe(&rakis_io_uring->sqring, NULL);
  if (!sqe) {
    return -EIO;
  }

  u64 user_data = (u64)buf;
  io_uring_prep_sqe_rw(sqe, IORING_OP_WRITE, fd, buf, count, offset, user_data);
  rakis_ring_prod_submit(&rakis_io_uring->sqring);

#if defined(RAKIS_VERIFICATION) && !defined(RAKIS_SYMBOLIC)
  // we need the nudge as there is no monitor to do it for us
  syscall(SYS_io_uring_enter, rakis_io_uring->fd, 1, 1, 0, 0);
#endif

  return io_uring_wait_for_exact_cqe(&rakis_io_uring->cqring, user_data);
}/*}}}*/

int rakis_init_pal_io_urings(struct rakis_io_uring_cfg* io_uring_cfg, struct rakis_pal* rakis_pal){/*{{{*/
#ifdef RAKIS_VERIFICATION
  struct rakis_io_uring_pool* rakis_io_uring_pool = &g_rakis_io_uring_pool;

#else
  struct pal_public_state* pal_public_state = PalGetPalPublicState();
  struct rakis_io_uring_pool* rakis_io_uring_pool = &pal_public_state->rakis_io_uring_pool;
#endif

  rakis_io_uring_pool->size  =  io_uring_cfg->io_urings_num;

  rakis_io_uring_pool->rakis_io_urings = calloc(rakis_io_uring_pool->size, sizeof(struct rakis_io_uring));
  if (!rakis_io_uring_pool->rakis_io_urings) {
    log_error("Could not allocate rakis io_urings pool");
    return -1;
  }

  for (u32 i = 0; i < rakis_io_uring_pool->size; i++) {
    if(rakis_init_pal_io_uring(io_uring_cfg, &rakis_pal->io_urings[i], &rakis_io_uring_pool->rakis_io_urings[i]) < 0){;
      log_error("rakis io_uring init failed");
      return -1;
    }
  }

  return 0;
}/*}}}*/
