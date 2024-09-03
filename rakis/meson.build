pal_rakis_sources = []
pal_rakis_sgx_sources = []
pal_rakis_direct_sources = []
pal_rakis_linux_common_sources = []

libos_rakis_sources = []
rakis_includes = []
rakis_cflag_def = []

if enable_rakis
  pal_rakis_sources = files('trusted/pal/pal.c')
  pal_rakis_sgx_sources = files('trusted/pal/pal_sgx.c', 'trusted/pal/initialization_data_checker.c', './trusted/pal/io_uring.c')
  pal_rakis_direct_sources = files('trusted/pal/pal_direct.c', 'trusted/pal/initialization_data_checker.c', './trusted/pal/io_uring.c')
  pal_rakis_linux_common_sources = files('untrusted/host_init.c', 'untrusted/monitor.c')

  libos_rakis_sources = files(
    'trusted/rakis_memcpy.c',
    'trusted/libos/init.c',
    'trusted/libos/netif.c',
    'trusted/libos/xsk.c',
    'trusted/libos/net_thread.c',
    'trusted/libos/rakis_socket.c',
    'trusted/libos/pktbpool.c',
    'trusted/libos/pktq.c',

    'trusted/libos/stack/stack.c',
    'trusted/libos/stack/rakis_misc.c',
    'trusted/libos/stack/rakis_rwlock.c',
    'trusted/libos/stack/rakis_event.c',

    'trusted/libos/stack/lwip/sockets.c',
    'trusted/libos/stack/lwip/udp.c',
    'trusted/libos/stack/lwip/inet_chksum.c',
    'trusted/libos/stack/lwip/netif.c',
    'trusted/libos/stack/lwip/err.c',
    'trusted/libos/stack/lwip/ethernet.c',
    'trusted/libos/stack/lwip/mem.c',
    'trusted/libos/stack/lwip/raw.c',
    'trusted/libos/stack/lwip/pbuf.c',
    'trusted/libos/stack/lwip/ipv4/etharp.c',
    'trusted/libos/stack/lwip/ipv4/ip4.c',
    'trusted/libos/stack/lwip/ipv4/ip4_addr.c',
    )

  rakis_includes = include_directories('include')

  if get_option('rakis_stats') == 'enabled'
    rakis_cflag_def = ['-DRAKIS=1', '-DRAKIS_STAT=1']
  else
    rakis_cflag_def = ['-DRAKIS=1']
  endif
endif
