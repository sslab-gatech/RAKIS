#ifndef RAKIS_LWIP_LWIPOPTS_H
#define RAKIS_LWIP_LWIPOPTS_H

#define SYS_LIGHTWEIGHT_PROT            0
#define NO_SYS                          0

// memory configuration
#define MEM_ALIGNMENT                  8U
#define MEM_LIBC_MALLOC                 1
#define MEM_USE_POOLS                   0
#define mem_clib_free                 free
#define mem_clib_malloc              malloc
#define mem_clib_calloc              calloc

// modules switches
#define LWIP_SOCKET                     1
#define LWIP_ARP                        1
#define LWIP_RAW                        1
#define LWIP_UDP                        1
#define LWIP_ICMP                       0
#define LWIP_TCP                        0
#define LWIP_DNS                        0
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_SNMP                       0
#define LWIP_IGMP                       0
#define LWIP_NETCONN                    0

// ip configuration
#define IP_FORWARD                      0
#define IP_OPTIONS_ALLOWED              1
#define IP_REASSEMBLY                   0
#define IP_FRAG                         0
#define IP_DEFAULT_TTL                 255

// pbuf configuration
#define PBUF_LINK_HLEN                  16

// loopback interface
#define LWIP_HAVE_LOOPIF                      0
#define LWIP_NETIF_LOOPBACK                   0
#define LWIP_NETIF_LOOPBACK_MULTITHREADING    0

// socket configuration
#define SO_REUSE                        1
#define LWIP_SO_SNDTIMEO                1
#define LWIP_SO_RCVTIMEO                1
#define LWIP_SO_RCVBUF                  1
#define LWIP_SO_LINGER                  1
#define LWIP_FIONREAD_LINUXMODE         1
#define CHECKSUM_CHECK_IP               0
#define CHECKSUM_CHECK_UDP              0
#define LWIP_CHECKSUM_ON_COPY           0
#define CHECKSUM_GEN_UDP                1

// ARP configuration
#define ARP_QUEUEING                    0
#define ARP_QUEUE_LEN                   0
#define ARP_TABLE_SIZE                 128
#define ETHARP_SUPPORT_STATIC_ENTRIES   1

// misc configuration
#define LWIP_STATS                      0
#define PPP_SUPPORT                     0
#define CHECKSUM_CHECK_TCP              0
#define CHECKSUM_CHECK_ICMP             0
#define LWIP_NETCONN_FULLDUPLEX         1

#define LWIP_SUPPORT_CUSTOM_PBUF 1
#endif /* LWIP_LWIPOPTS_H */
