#ifndef RAKIS_SOCKET_H
#define RAKIS_SOCKET_H

#include "libos_handle.h"
#include "rakis/linux_host.h"

#define ONLY_SOCKETS_FUNCTIONS
#include "lwip/sockets.h"

long rakis_poll_start(struct pollfd *fds, nfds_t nfds, struct rakis_poll_cb* poll_cb);
long rakis_poll_end(struct pollfd *fds, nfds_t nfds, struct rakis_poll_cb* poll_cb);
long rakis_socket(int family, int type, int protocol);
long rakis_listen(struct libos_handle* handle, int backlog);
long rakis_accept(struct libos_handle* handle, void* addr, int* addrlen, bool is_nonblocking);
long rakis_connect(struct libos_handle* handle, void* addr, int _addrlen);
long rakis_sendto(struct libos_handle* handle, void* buf, size_t len, unsigned int flags, void* addr, int addrlen);
long rakis_sendmsg(struct libos_handle* handle, struct msghdr* msg, unsigned int flags);
long rakis_sendmmsg(struct libos_handle* handle, struct mmsghdr* msg, unsigned int vlen, unsigned int flags);
long rakis_recvfrom(struct libos_handle* handle, void* buf, size_t len, unsigned int flags, void* addr, int* _addrlen);
long rakis_recvmsg(struct libos_handle* handle, struct msghdr* msg, unsigned int flags);
long rakis_recvmmsg(struct libos_handle* handle, struct mmsghdr* msg, unsigned int vlen, unsigned int flags);
long rakis_shutdown(struct libos_handle* handle, int how);
long rakis_getsockname(struct libos_handle* handle, void* addr, int* _addrlen);
long rakis_getpeername(struct libos_handle* handle, void* addr, int* _addrlen);
long rakis_setsockopt(struct libos_handle* handle, int level, int optname, char* optval, int optlen);
long rakis_getsockopt(struct libos_handle* handle, int level, int optname, char* optval, int* optlen);
long rakis_bind(struct libos_handle* handle, void* addr, int _addrlen);

#endif
