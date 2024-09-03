#include "lwip/sockets.h"
#include "rakis/fuzz/fuzz_sockets.h"
#include "rakis/fuzz/host.h"
#include <stdio.h>

enum SOCK_TYPE_COMP{
  ONLY_UDP = 0,
  UDP_RAW  = 1,
};

static int start_port = 57344;
static int num_fuzz_udp_sockets = 4;
static int fuzz_udp_socket_fds[] = {-1, -1, -1, -1};
static int fuzz_raw_socket_fd = -1;

void echo_packets(int fd){
  struct sockaddr_in client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  char buf[1024];
  memset(buf, 0, sizeof(buf));

  do {
    int ret = lwip_recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&client_addr, &client_addr_len);
    if(ret < 0){
      printf("Could not receive from fuzz socket: %d\n", ret);
      break;
    }

    printf("Received %d bytes from fuzz socket\n", ret);
    printf("%s\n", buf);

    printf("connecting to %d\n", client_addr.sin_port);
    ret = lwip_connect(fd, (struct sockaddr*)&client_addr, client_addr_len);
    if(ret < 0){
      printf("Could not connect to fuzz socket\n");
      break;
    }

    ret = lwip_sendto(fd, buf, ret, 0, (struct sockaddr*)&client_addr, client_addr_len);
    if(ret < 0){
      printf("Could not send to fuzz socket\n");
      break;
    }
  } while(1);
}

static void set_all_socket_options(int s) {
    int optval_int = 1;  // Example value for integer-based options
    struct timeval optval_timeval = {10, 0};  // Example value for timeval-based options
    struct linger optval_linger = {1, 10};  // Example value for linger-based options
    // Assuming a struct for device name; adjust as necessary
    struct sockaddr optval_sockaddr; 

    socklen_t optlen_int = sizeof(int);
    socklen_t optlen_timeval = sizeof(struct timeval);
    socklen_t optlen_linger = sizeof(struct linger);
    socklen_t optlen_sockaddr = sizeof(struct sockaddr);

    // Set SOL_SOCKET level options
    lwip_setsockopt(s, SOL_SOCKET, SO_BROADCAST, &optval_int, optlen_int);
    lwip_setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &optval_int, optlen_int);
    lwip_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval_int, optlen_int);
    lwip_setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &optval_timeval, optlen_timeval);
    lwip_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &optval_timeval, optlen_timeval);
    lwip_setsockopt(s, SOL_SOCKET, SO_RCVBUF, &optval_int, optlen_int);
    lwip_setsockopt(s, SOL_SOCKET, SO_LINGER, &optval_linger, optlen_linger);
    lwip_setsockopt(s, SOL_SOCKET, SO_NO_CHECK, &optval_int, optlen_int);
    lwip_setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, &optval_sockaddr, optlen_sockaddr);  // Note: Adjust as necessary

    // Set IPPROTO_IP level options
    lwip_setsockopt(s, IPPROTO_IP, IP_TTL, &optval_int, optlen_int);
    lwip_setsockopt(s, IPPROTO_IP, IP_TOS, &optval_int, optlen_int);
}

static void get_all_socket_options(int s) {
  int optval_int;
  struct timeval optval_timeval;
  struct linger optval_linger;
  socklen_t optlen_int = sizeof(int);
  socklen_t optlen_timeval = sizeof(struct timeval);
  socklen_t optlen_linger = sizeof(struct linger);

  // Fetch options one by one
  lwip_getsockopt(s, SOL_SOCKET, SO_BROADCAST, &optval_int, &optlen_int);
  lwip_getsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &optval_int, &optlen_int);
  lwip_getsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval_int, &optlen_int);
  lwip_getsockopt(s, SOL_SOCKET, SO_TYPE, &optval_int, &optlen_int);
  lwip_getsockopt(s, SOL_SOCKET, SO_ERROR, &optval_int, &optlen_int);
  lwip_getsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &optval_timeval, &optlen_timeval);
  lwip_getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &optval_timeval, &optlen_timeval);
  lwip_getsockopt(s, SOL_SOCKET, SO_RCVBUF, &optval_int, &optlen_int);
  lwip_getsockopt(s, SOL_SOCKET, SO_SNDBUF, &optval_int, &optlen_int);
  lwip_getsockopt(s, SOL_SOCKET, SO_LINGER, &optval_linger, &optlen_linger);
  lwip_getsockopt(s, SOL_SOCKET, SO_NO_CHECK, &optval_int, &optlen_int);
  lwip_getsockopt(s, IPPROTO_IP, SO_SNDBUF, &optval_int, &optlen_int);
  lwip_getsockopt(s, IPPROTO_IP, SO_LINGER, &optval_linger, &optlen_linger);
  lwip_getsockopt(s, IPPROTO_IP, SO_NO_CHECK, &optval_int, &optlen_int);
}

static void get_addrname(int fd){
  struct sockaddr_in client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  int ret = lwip_getpeername(fd, (struct sockaddr*)&client_addr, &client_addr_len);
  if(ret < 0){
    printf("Could not get peer name\n");
  }else{
    printf("Peer name: %d.%d.%d.%d:%d\n",
        client_addr.sin_addr.s_addr & 0xFF,
        (client_addr.sin_addr.s_addr >> 8) & 0xFF,
        (client_addr.sin_addr.s_addr >> 16) & 0xFF,
        (client_addr.sin_addr.s_addr >> 24) & 0xFF,
        client_addr.sin_port);
  }
  ret = lwip_getsockname(fd, (struct sockaddr*)&client_addr, &client_addr_len);
  if(ret < 0){
    printf("Could not get sock name\n");
  }else{
    printf("Sock name: %d.%d.%d.%d:%d\n",
        client_addr.sin_addr.s_addr & 0xFF,
        (client_addr.sin_addr.s_addr >> 8) & 0xFF,
        (client_addr.sin_addr.s_addr >> 16) & 0xFF,
        (client_addr.sin_addr.s_addr >> 24) & 0xFF,
        client_addr.sin_port);
  }
}

static void fuzz_one_udp_socket(int fd){
  echo_packets(fd);

  get_addrname(fd);
  set_all_socket_options(fd);
  get_all_socket_options(fd);

  lwip_close(fd);
}

static void fuzz_udp_sockets(void){
  for (int i=0; i < num_fuzz_udp_sockets; i++) {
    if(fuzz_udp_socket_fds[i] < 0){
      continue;
    }
    fuzz_one_udp_socket(fuzz_udp_socket_fds[i]);
  }
}

static void fuzz_raw_socket(void){
  printf("Fuzzing raw socket\n");
  echo_packets(fuzz_raw_socket_fd);
}

void fuzz_sockets(void){
  fuzz_udp_sockets();
  fuzz_raw_socket();
}

static int create_raw_socket(void){/*{{{*/
  fuzz_raw_socket_fd = lwip_socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  if(fuzz_raw_socket_fd < 0){
    printf("Could not create fuzz raw socket\n");
    return -1;
  }

  struct sockaddr_in host_addr;
  host_addr.sin_family = AF_INET;
  host_addr.sin_port = 0;
  host_addr.sin_addr.s_addr = 0x100320a; // 10.50.0.1
  int ret = lwip_bind(fuzz_raw_socket_fd, (struct sockaddr*)&host_addr, sizeof(host_addr));
  if(ret < 0){
    printf("Could not bind fuzz socket\n");
    return -1;
  }

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 1; // this should be enough because we are not waiting for anything
  ret = lwip_setsockopt(fuzz_raw_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  if(ret < 0){
    printf("Could not set fuzz socket timeout\n");
    return -1;
  }

  return 0;
}/*}}}*/

static int create_udp_sockets(void){/*{{{*/
  for(int i = 0; i < num_fuzz_udp_sockets; i++){
    fuzz_udp_socket_fds[i] = lwip_socket(AF_INET, SOCK_DGRAM, 0);
    if(fuzz_udp_socket_fds[i] < 0){
      printf("Could not create fuzz socket\n");
      return -1;
    }

    struct sockaddr_in host_addr;
    host_addr.sin_family = AF_INET;
    host_addr.sin_port = lwip_htons(start_port + i);
    host_addr.sin_addr.s_addr = 0x100320a; // 10.50.0.1
    int ret = lwip_bind(fuzz_udp_socket_fds[i], (struct sockaddr*)&host_addr, sizeof(host_addr));
    if(ret < 0){
      printf("Could not bind fuzz socket\n");
      return -1;
    }

    // set recv timeout to 500 ms
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1;
    ret = lwip_setsockopt(fuzz_udp_socket_fds[i], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if(ret < 0){
      printf("Could not set fuzz socket timeout\n");
      return -1;
    }
  }
  return 0;
}/*}}}*/

int prep_fuzz_sockets(void){
  create_udp_sockets();
  create_raw_socket();

  printf("Fuzz sockets created\n");
  return 0;
}
