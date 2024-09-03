#include <asm/ioctls.h>

#include "rakis/rakis_socket.h"
#include "libos_fs.h"
#include "perm.h"
#include "stat.h"
#include "libos_utils.h"
#include "rakis/stack/rakis_misc.h"

static int rakis_get_neg_errno(void) {
  return -RAKIS_GET_THREAD_STRG(rerrno);
}

long rakis_listen(struct libos_handle* handle, int backlog) {
    return -EOPNOTSUPP;
}

long rakis_accept(struct libos_handle* handle, void* addr, int* addrlen, bool is_nonblocking) {
    return -EOPNOTSUPP;
}

long rakis_poll_start(struct pollfd *fds, nfds_t nfds, struct rakis_poll_cb* poll_cb){
  int ret = lwip_poll_start(fds, nfds, poll_cb);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_poll_end(struct pollfd *fds, nfds_t nfds, struct rakis_poll_cb* poll_cb){
  int ret = lwip_poll_end(fds, nfds, poll_cb);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_socket(int family, int type, int protocol) {
  struct libos_handle* handle = get_new_handle();
  if (!handle) {
    return -ENOMEM;
  }

  handle->type = TYPE_RAKIS;
  handle->fs = &rakis_builtin_fs;
  handle->acc_mode = MAY_READ | MAY_WRITE;

  int flags = type & ~SOCK_TYPE_MASK;
  bool is_nonblocking = flags & SOCK_NONBLOCK;
  handle->flags = O_RDWR | (is_nonblocking ? O_NONBLOCK : 0);

  int ret = 0;
  int rakis_sock = lwip_socket(family, type, protocol);

  if (rakis_sock >= 0) {
    handle->info.rakis_sock = rakis_sock;
    ret = set_new_fd_handle(handle, 0, NULL);
  }else{
    ret = rakis_get_neg_errno();
  }

  put_handle(handle);
  return ret;
}

long rakis_bind(struct libos_handle* handle, void* addr, int _addrlen) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_bind(handle->info.rakis_sock, addr, _addrlen);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_connect(struct libos_handle* handle, void* addr, int _addrlen) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_connect(handle->info.rakis_sock, addr, _addrlen);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_sendto(struct libos_handle* handle, void* buf, size_t len, unsigned int flags, void* addr, int addrlen) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_sendto(handle->info.rakis_sock, buf, len, flags, addr, addrlen);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_sendmsg(struct libos_handle* handle, struct msghdr* msg, unsigned int flags) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_sendmsg(handle->info.rakis_sock, msg, flags);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_sendmmsg(struct libos_handle* handle, struct mmsghdr* msg, unsigned int vlen, unsigned int flags) {
  assert(handle->type == TYPE_RAKIS);

  for (size_t i = 0; i < vlen; i++) {
    struct msghdr* hdr = &msg[i].msg_hdr;

    size_t total_len;
    total_len = lwip_sendmsg(handle->info.rakis_sock, hdr, flags);
    if (total_len < 0) {
      if (i == 0) {
        return rakis_get_neg_errno();
      }else{
        return i;
      }
    }

    msg[i].msg_len = total_len;
  }

  return vlen;
}

long rakis_recvfrom(struct libos_handle* handle, void* buf, size_t len, unsigned int flags, void* addr, int* _addrlen) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_recvfrom(handle->info.rakis_sock, buf, len, flags, addr, _addrlen);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_recvmsg(struct libos_handle* handle, struct msghdr* msg, unsigned int flags) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_recvmsg(handle->info.rakis_sock, msg, flags);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_recvmmsg(struct libos_handle* handle, struct mmsghdr* msg, unsigned int vlen, unsigned int flags) {
  assert(handle->type == TYPE_RAKIS);

  for (size_t i = 0; i < vlen; i++) {
    struct msghdr* hdr = &msg[i].msg_hdr;

    size_t total_len;
    total_len = lwip_recvmsg(handle->info.rakis_sock, hdr, flags);
    if (total_len < 0) {
      if (i == 0) {
        return rakis_get_neg_errno();
      }else{
        return i;
      }
    }

    msg[i].msg_len = total_len;
  }

  return vlen;
}

long rakis_shutdown(struct libos_handle* handle, int how) {
  assert(handle->type == TYPE_RAKIS);

  int ret = -1;
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_getsockname(struct libos_handle* handle, void* addr, int* _addrlen) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_getsockname(handle->info.rakis_sock, addr, _addrlen);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_getpeername(struct libos_handle* handle, void* addr, int* _addrlen) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_getpeername(handle->info.rakis_sock, addr, _addrlen);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_setsockopt(struct libos_handle* handle, int level, int optname, char* optval, int optlen) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_setsockopt(handle->info.rakis_sock, level, optname, optval, optlen);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

long rakis_getsockopt(struct libos_handle* handle, int level, int optname, char* optval, int* optlen) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_getsockopt(handle->info.rakis_sock, level, optname, optval, optlen);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

static int rakis_close(struct libos_handle* handle) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_close(handle->info.rakis_sock);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

static ssize_t rakis_read(struct libos_handle* handle, void* buf, size_t size, file_off_t* pos) {
  __UNUSED(pos);
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_read(handle->info.rakis_sock, buf, size);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

static ssize_t rakis_write(struct libos_handle* handle, const void* buf, size_t size, file_off_t* pos) {
  __UNUSED(pos);
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_write(handle->info.rakis_sock, buf, size);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

static ssize_t rakis_readv(struct libos_handle* handle, struct iovec* iov, size_t iov_len,
    file_off_t* pos) {
  __UNUSED(pos);
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_readv(handle->info.rakis_sock, iov, iov_len);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

static ssize_t rakis_writev(struct libos_handle* handle, struct iovec* iov, size_t iov_len,
    file_off_t* pos) {
  __UNUSED(pos);
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_writev(handle->info.rakis_sock, iov, iov_len);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

static int rakis_hstat(struct libos_handle* handle, struct stat* stat) {
  __UNUSED(handle);
  assert(stat);
  assert(handle->type == TYPE_RAKIS);

  memset(stat, 0, sizeof(*stat));

  stat->st_dev = 0;
  stat->st_ino = 0;
  stat->st_mode = S_IFSOCK | PERM_rwxrwxrwx;
  stat->st_nlink = 1;
  stat->st_blksize = PAGE_SIZE;
  return 0;
}

static int rakis_setflags(struct libos_handle* handle, unsigned int flags, unsigned int mask) {
  assert(mask != 0);
  assert((flags & ~mask) == 0);
  assert(handle->type == TYPE_RAKIS);

  if (!WITHIN_MASK(flags, O_NONBLOCK)) {
    return -EINVAL;
  }

  bool is_nonblocking = (flags & O_NONBLOCK);
  if (is_nonblocking) {
    handle->flags |= O_NONBLOCK;
  }else{
    handle->flags &= ~O_NONBLOCK;
  }

  int ret = lwip_fcntl(handle->info.rakis_sock, F_SETFL, flags);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

static int rakis_ioctl(struct libos_handle* handle, unsigned int cmd, unsigned long arg) {
  assert(handle->type == TYPE_RAKIS);

  int ret = lwip_ioctl(handle->info.rakis_sock, cmd, &arg);
  if (ret < 0) {
    return rakis_get_neg_errno();
  }
  return ret;
}

static struct libos_fs_ops rakis_fs_ops = {
  .close    = rakis_close,
  .read     = rakis_read,
  .write    = rakis_write,
  .readv    = rakis_readv,
  .writev   = rakis_writev,
  .hstat    = rakis_hstat,
  .setflags = rakis_setflags,
  .ioctl    = rakis_ioctl,
};

struct libos_fs rakis_builtin_fs = {
  .name   = "rakis",
  .fs_ops = &rakis_fs_ops,
};
