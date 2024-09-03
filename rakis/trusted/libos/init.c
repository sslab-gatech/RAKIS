#include "libos_utils.h"
#include "libos_vma.h"
#include "rakis/linux_io_uring.h"
#include "rakis/net_thread.h"
#include "rakis/netif.h"
#include "rakis/netif.h"
#include "rakis/pal.h"
#include "rakis/rakis.h"
#include "rakis/stack/stack.h"
#include "rakis/xsk.h"
#include "toml.h"
#include "toml_utils.h"

struct rakis_config* g_rakis_config = NULL;
struct rakis_monitor_pal* g_rakis_monitor_pal = NULL;
struct libos_thread* g_monitor_thread = NULL;

struct new_net_thread_args {
  u16 rakis_thread_id;
  u32 thread_index;
  struct rakis_xsk** xsks;
  int num_xsks;
};

static void debug_print_rakis_config(void){/*{{{*/
#ifdef DEBUG
  log_debug("****************************************");
  log_debug("RAKIS configurations options:");
  log_debug("********************");
  log_debug("Network configurations:");
  log_debug("Number of net threads: %u", g_rakis_config->net_threads_num);
  log_debug("total xsks: %u", g_rakis_config->total_xsks_num);
  log_debug("Number of netifs: %u", g_rakis_config->netifs_num);

  for(u32 i=0; i< g_rakis_config->netifs_num; i++){
    struct rakis_netif_cfg* netif_cfg = &g_rakis_config->netifs_cfg[i];
    log_debug("  netifs[%d].interface_name: %s",       i, netif_cfg->interface_name);
    log_debug("  netifs[%d].ip_addr: %d.%d.%d.%d", i,
         netif_cfg->ip_addr & 0xff,
        (netif_cfg->ip_addr >> 8) & 0xff,
        (netif_cfg->ip_addr >> 16) & 0xff,
        (netif_cfg->ip_addr >> 24) & 0xff);
    log_debug("  netifs[%d].gw_addr: %d.%d.%d.%d", i,
         netif_cfg->gw_addr & 0xff,
        (netif_cfg->gw_addr >> 8) & 0xff,
        (netif_cfg->gw_addr >> 16) & 0xff,
        (netif_cfg->gw_addr >> 24) & 0xff);
    log_debug("  netifs[%d].netmask: %d.%d.%d.%d", i,
         netif_cfg->netmask & 0xff,
        (netif_cfg->netmask >> 8) & 0xff,
        (netif_cfg->netmask >> 16) & 0xff,
        (netif_cfg->netmask >> 24) & 0xff);
    log_debug("  netifs[%d].mac_addr: %02x:%02x:%02x:%02x:%02x:%02x", i,
        (unsigned char) netif_cfg->mac_addr[0],
        (unsigned char) netif_cfg->mac_addr[1],
        (unsigned char) netif_cfg->mac_addr[2],
        (unsigned char) netif_cfg->mac_addr[3],
        (unsigned char) netif_cfg->mac_addr[4],
        (unsigned char) netif_cfg->mac_addr[5]);
    log_debug("  netifs[%d].mtu: %u", i, netif_cfg->mtu);

    log_debug("  Number of xsks in interface[%d]: %u", i, netif_cfg->xsks_num);
    for(u32 j=0; j<netif_cfg->xsks_num; j++){
      struct rakis_xsk_cfg* rakis_xsk_cfg = &netif_cfg->xsks_cfg[j];
      log_debug("    xsks[%d].control process path: %s", j, rakis_xsk_cfg->ctrl_prcs_path);
      log_debug("    xsks[%d].qid: %d",                  j, rakis_xsk_cfg->qid);
      log_debug("    xsks[%d].fill_ring_size: %u",       j, rakis_xsk_cfg->fill_ring_size);
      log_debug("    xsks[%d].compl_ring_size: %u",      j, rakis_xsk_cfg->compl_ring_size);
      log_debug("    xsks[%d].rx_ring_size: %u",         j, rakis_xsk_cfg->rx_ring_size);
      log_debug("    xsks[%d].tx_ring_size: %u",         j, rakis_xsk_cfg->tx_ring_size);
      log_debug("    xsks[%d].frame_size: %u",           j, rakis_xsk_cfg->frame_size);
      log_debug("    xsks[%d].umem_size: %u",            j, rakis_xsk_cfg->umem_size);
      log_debug("    xsks[%d].zero_copy: %s",            j, rakis_xsk_cfg->zero_copy? "true" : "false");
      log_debug("    xsks[%d].needs_wakeup: %s",         j, rakis_xsk_cfg->needs_wakeup? "true" : "false");
      log_debug("    *****");
    }

    log_debug("  **********");
  }

  log_debug("********************");
  log_debug("io_uring configurations:");
  log_debug("Number of io_urings: %u", g_rakis_config->io_urings_cfg.io_urings_num);
  log_debug("Number of entries per io_uring: %u", g_rakis_config->io_urings_cfg.entries_num);

  log_debug("********************");
  log_debug("ARP table:");
  log_debug("ARP table size: %u", g_rakis_config->arp_table_size);
  for(u32 j=0; j<g_rakis_config->arp_table_size; j++){
    struct rakis_arp_entry* arp = &g_rakis_config->arp_table[j];
    log_debug("  %d.%d.%d.%d -- %02x:%02x:%02x:%02x:%02x:%02x", arp->ip_addr & 0xff,
        (arp->ip_addr >> 8) & 0xff,
        (arp->ip_addr >> 16) & 0xff,
        (arp->ip_addr >> 24) & 0xff,
        (unsigned char) arp->mac_addr[0],
        (unsigned char) arp->mac_addr[1],
        (unsigned char) arp->mac_addr[2],
        (unsigned char) arp->mac_addr[3],
        (unsigned char) arp->mac_addr[4],
        (unsigned char) arp->mac_addr[5]);
    log_debug("**********");
  }
  log_debug("****************************************");
#endif
}/*}}}*/

static int mac_string_to_bytes(const char *mac_str, size_t len, unsigned char *mac_bytes) {/*{{{*/
  int i = 0;
  char byte_str[3] = {0};
  char *endptr = NULL;

  // Ensure that the MAC string has the correct format (i.e. six bytes separated by colons)
  if (len != 17 || mac_str[2] != ':' || mac_str[5] != ':'
      || mac_str[8] != ':' || mac_str[11] != ':' || mac_str[14] != ':') {
    return -1;
  }

  // Iterate through the MAC string, extracting each byte
  for (i = 0; i < 6; i++) {
    // Extract two characters to form a byte string
    byte_str[0] = mac_str[i * 3];
    byte_str[1] = mac_str[i * 3 + 1];
    byte_str[2] = '\0';

    // Convert the byte string to an integer
    long int byte = strtol(byte_str, &endptr, 16);

    // Check for invalid characters
    if (*endptr != '\0') {
      return -1;
    }

    // Store the byte in the output array
    mac_bytes[i] = (unsigned char)byte;
  }
  return 0;
}/*}}}*/

static int inet_pton4(const char* src, size_t len, void* dstp) {/*{{{*/
    unsigned char* dst = (unsigned char*)dstp;
    const char* end    = src + len;
    int saw_digit, octets, ch;
    unsigned char tmp[NS_INADDRSZ], *tp;

    saw_digit   = 0;
    octets      = 0;
    *(tp = tmp) = 0;
    while (src < end && (ch = *src++) != '\0') {
        if (ch >= '0' && ch <= '9') {
            uint32_t new = *tp * 10 + (ch - '0');

            if (saw_digit && *tp == 0)
                return 0;
            if (new > 255)
                return 0;
            *tp = new;
            if (!saw_digit) {
                if (++octets > 4)
                    return 0;
                saw_digit = 1;
            }
        } else if (ch == '.' && saw_digit) {
            if (octets == 4)
                return 0;
            *++tp     = 0;
            saw_digit = 0;
        } else {
            return 0;
        }
    }
    if (octets < 4)
        return 0;
    memcpy(dst, tmp, NS_INADDRSZ);
    return 1;
}/*}}}*/

static int parse_xsk_config(struct rakis_netif_cfg* netif_cfg, toml_array_t* xsks_array){/*{{{*/
  int ret;

  for(unsigned int i=0; i < netif_cfg->xsks_num; i++){
    toml_table_t* xsk_table = toml_table_at(xsks_array, i);
    struct rakis_xsk_cfg* current_xsk_cfg = &netif_cfg->xsks_cfg[i];

    {
      char* temp;
      ret = toml_string_in(xsk_table, "ctrl_prcs_path", &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].xsks[%d].ctrl_prcs_path'", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      if(!temp){
        log_error("'rakis.netifs[%s].xsks[%d].ctrl_prcs_path' is required", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      size_t path_len = strnlen(temp, sizeof(current_xsk_cfg->ctrl_prcs_path));
      if (path_len == sizeof(current_xsk_cfg->ctrl_prcs_path)) {
        log_error("control process path name (%s) is too long!", temp);
        return -EINVAL;
      }
      memcpy(current_xsk_cfg->ctrl_prcs_path, temp, path_len);
    }

    {
      int64_t temp;
      ret = toml_int_in(xsk_table, "qid", 0, &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].xsks[%d].qid'", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      current_xsk_cfg->qid = temp;
    }

    {
      int64_t temp;
      ret = toml_int_in(xsk_table, "rx_ring_size", RAKIS_DEF_XDP_RX_RING_SIZE, &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].xsks[%d].rx_ring_size'", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      if (!temp) {
        log_error("'rakis.netifs[%s].xsks[%d].rx_ring_size' cannot be zero", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      if ((temp & (temp - 1))) {
        log_error("'rakis.netifs[%s].xsks[%d].rx_ring_size' must be a power of two", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      current_xsk_cfg->rx_ring_size = temp;
      current_xsk_cfg->fill_ring_size = temp * 2;
    }

    {
      int64_t temp;
      ret = toml_int_in(xsk_table, "tx_ring_size", RAKIS_DEF_XDP_TX_RING_SIZE, &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].xsks[%d].tx_ring_size'", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      if (!temp) {
        log_error("'rakis.netifs[%s].xsks[%d].tx_ring_size' cannot be zero", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      if ((temp & (temp - 1))) {
        log_error("'rakis.netifs[%s].xsks[%d].tx_ring_size' must be a power of two", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      current_xsk_cfg->tx_ring_size = temp;
      current_xsk_cfg->compl_ring_size = temp;
    }

    {
      int64_t temp;
      ret = toml_int_in(xsk_table, "frame_size", RAKIS_DEF_XDP_FRAME_SIZE, &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].xsks[%d].frame_size'", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      if (!temp) {
        log_error("'rakis.netifs[%s].xsks[%d].frame_size' cannot be zero", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      if ((temp & (temp - 1))) {
        log_error("'rakis.netifs[%s].xsks[%d].frame_size' must be a power of two", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      current_xsk_cfg->frame_size = temp;
    }

    {
      int64_t temp;
      ret = toml_int_in(xsk_table, "umem_size", RAKIS_DEF_XDP_UMEM_SIZE, &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].xsks[%d].umem_size'", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      if (!temp) {
        log_error("'rakis.netifs[%s].xsks[%d].umem_size' cannot be zero", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      if ((temp % current_xsk_cfg->frame_size) != 0) {
        log_error("Size of UMEM area needs to be a multiple of the frame size for XDP socket at index %d", i);
        return -EINVAL;
      }
      current_xsk_cfg->umem_size = temp;
    }

    {
      bool iszerocopy;
      ret = toml_bool_in(xsk_table, "zero_copy", true,
          &iszerocopy);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].xsks[%d].zero_copy'", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      current_xsk_cfg->zero_copy = iszerocopy;
    }

    {
      bool needs_wakeup;
      ret = toml_bool_in(xsk_table, "needs_wakeup", false,
          &needs_wakeup);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].xsks[%d].needs_wakeup'", netif_cfg->interface_name, i);
        return -EINVAL;
      }
      current_xsk_cfg->needs_wakeup = needs_wakeup;
    }
  }

  g_rakis_config->total_xsks_num += netif_cfg->xsks_num;
  return 0;
}/*}}}*/

static int parse_netif_config(toml_array_t* netifs_array){/*{{{*/
  int ret;

  for(unsigned int i=0; i < g_rakis_config->netifs_num; i++){
    toml_table_t* netif_table = toml_table_at(netifs_array, i);
    struct rakis_netif_cfg* current_netif_cfg = &g_rakis_config->netifs_cfg[i];

    {
      char* temp;
      ret = toml_string_in(netif_table, "interface_name",
          &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%d].interface_name'", i);
        return -EINVAL;
      }
      if(!temp){
        log_error("'rakis.netifs[%d].interface_name' is required", i);
        return -EINVAL;
      }
      size_t intrf_len = strnlen(temp, sizeof(current_netif_cfg->interface_name));
      if (intrf_len == sizeof(current_netif_cfg->interface_name)) {
        log_error("Interface name (%s) is too long!", temp);
        return -EINVAL;
      }
      memcpy(current_netif_cfg->interface_name, temp, intrf_len);
    }

    {
      char* temp;
      ret = toml_string_in(netif_table, "ip_addr",
          &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].ip_addr'", current_netif_cfg->interface_name);
        return -EINVAL;
      }
      if(!temp){
        log_error("'rakis.netifs[%s].ip_addr' is required", current_netif_cfg->interface_name);
        return -EINVAL;
      }
      int len = strnlen(temp, 16);
      if (len == 16) {
        log_error("IP (%s) is too long!", temp);
        return -EINVAL;
      }
      ret = inet_pton4(temp, len, &current_netif_cfg->ip_addr);
      if (!ret) {
        log_error("IP (%s) is invalid!", temp);
        return -EINVAL;
      }
    }

    {
      char* temp;
      ret = toml_string_in(netif_table, "gw_addr",
          &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].gw_addr'", current_netif_cfg->interface_name);
        return -EINVAL;
      }
      if(!temp){
        log_error("'rakis.netifs[%s].gw_addr' is required", current_netif_cfg->interface_name);
        return -EINVAL;
      }
      int len = strnlen(temp, 16);
      if (len == 16) {
        log_error("Gateway IP (%s) is too long!", temp);
        return -EINVAL;
      }
      ret = inet_pton4(temp, len, &current_netif_cfg->gw_addr);
      if (!ret) {
        log_error("Gateway IP (%s) is invalid!", temp);
        return -EINVAL;
      }
    }

    {
      char* temp;
      ret = toml_string_in(netif_table, "netmask",
          &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].netmask'", current_netif_cfg->interface_name);
        return -EINVAL;
      }
      if(!temp){
        log_error("'rakis.netifs[%s].netmask' is required", current_netif_cfg->interface_name);
        return -EINVAL;
      }
      int len = strnlen(temp, 16);
      if (len == 16) {
        log_error("Netmask (%s) is too long!", temp);
        return -EINVAL;
      }
      ret = inet_pton4(temp, len, &current_netif_cfg->netmask);
      if (!ret) {
        log_error("Netmask (%s) is invalid!", temp);
        return -EINVAL;
      }
    }

    {
      char* temp;
      ret = toml_string_in(netif_table, "mac_addr",
          &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].mac_addr'", current_netif_cfg->interface_name);
        return -EINVAL;
      }
      if(!temp){
        log_error("'rakis.netifs[%s].mac_addr' is required", current_netif_cfg->interface_name);
        return -EINVAL;
      }
      int len = strnlen(temp, 18);
      if (len == 18) {
        log_error("MAC (%s) is too long!", temp);
        return -EINVAL;
      }
      ret = mac_string_to_bytes(temp, len, current_netif_cfg->mac_addr);
      if (ret < 0) {
        log_error("MAC (%s) is invalid!", temp);
        return -EINVAL;
      }
    }

    {
      int64_t temp;
      ret = toml_int_in(netif_table, "mtu", RAKIS_DEF_XDP_MTU, &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.netifs[%s].mtu'", current_netif_cfg->interface_name);
        return -EINVAL;
      }
      if (!temp) {
        log_error("'rakis.netifs[%s].mtu' cannot be zero", current_netif_cfg->interface_name);
        return -EINVAL;
      }
      current_netif_cfg->mtu = temp;
    }

    toml_array_t* xsks_array = toml_array_in(netif_table, "xsks");
    if (!xsks_array){
      log_error("Cannot parse 'rakis.netifs[%s].xsks'", current_netif_cfg->interface_name);
      return -EINVAL;
    }

    current_netif_cfg->xsks_num = toml_array_nelem(xsks_array);

    current_netif_cfg->xsks_cfg = calloc(current_netif_cfg->xsks_num, sizeof(struct rakis_xsk_cfg));
    if(!current_netif_cfg->xsks_cfg){
      return -1;
    }

    if (parse_xsk_config(current_netif_cfg, xsks_array) < 0) {
      log_error("Error while parsing RAKIS xsks config for netif %s", current_netif_cfg->interface_name);
      return -EINVAL;
    }

  } // ends of iterating over netifs

  return 0;
}/*}}}*/

static int parse_io_uring_config(toml_table_t* io_uring_table){/*{{{*/
  int ret = 0;

  {
    // (rakis) TODO: this should be set equal to thread_max configured in gramine
    int64_t temp;
    ret = toml_int_in(io_uring_table, "io_urings_num", 0, &temp);
    if (ret < 0) {
      log_error("Cannot parse 'rakis.io_uring.io_urings_num'");
      return -EINVAL;
    }
    if (!temp) {
      log_error("'rakis.io_uring.io_urings_num' must be set to non-zero");
      return -EINVAL;
    }
    g_rakis_config->io_urings_cfg.io_urings_num = temp;
  }

  {
    int64_t temp;
    ret = toml_int_in(io_uring_table, "num_entries", RAKIS_DEF_IO_URING_ENTRIES, &temp);
    if (ret < 0) {
      log_error("Cannot parse 'rakis.io_uring.num_entries'");
      return -EINVAL;
    }
    if (!temp) {
      log_error("'rakis.io_uring.num_entries' cannot be zero");
      return -EINVAL;
    }
    if ((temp & (temp - 1))) {
      log_error("'rakis.io_uring.num_entries' must be a power of two");
      return -EINVAL;
    }
    g_rakis_config->io_urings_cfg.entries_num = temp;
  }

  return ret;
}/*}}}*/

static int parse_arp_table(toml_array_t* arp_array){/*{{{*/
  int ret;

  for(unsigned int i=0; i < g_rakis_config->arp_table_size; i++){
    toml_table_t* arp_table_entry_toml = toml_table_at(arp_array, i);
    struct rakis_arp_entry* current_arp_entry_cfg = &g_rakis_config->arp_table[i];

    {
      char* temp;
      ret = toml_string_in(arp_table_entry_toml, "ip_addr",
          &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.arp_table[%d].ip_addr'", i);
        return -EINVAL;
      }
      if(!temp){
        log_error("'rakis.arp_table[%d].ip_addr' is required", i);
        return -EINVAL;
      }
      int len = strnlen(temp, 16);
      if (len == 16) {
        log_error("IP (%s) is too long!", temp);
        return -EINVAL;
      }
      ret = inet_pton4(temp, len, &current_arp_entry_cfg->ip_addr);
      if (!ret) {
        log_error("IP (%s) is invalid!", temp);
        return -EINVAL;
      }
    }

    {
      char* temp;
      ret = toml_string_in(arp_table_entry_toml, "mac_addr",
          &temp);
      if (ret < 0) {
        log_error("Cannot parse 'rakis.arp_table[%d].mac_addr'", i);
        return -EINVAL;
      }
      if(!temp){
        log_error("'rakis.arp_table[%d].mac_addr' is required", i);
        return -EINVAL;
      }
      int len = strnlen(temp, 18);
      if (len == 18) {
        log_error("MAC (%s) is too long!", temp);
        return -EINVAL;
      }
      ret = mac_string_to_bytes(temp, len, current_arp_entry_cfg->mac_addr);
      if (ret < 0) {
        log_error("MAC (%s) is invalid!", temp);
        return -EINVAL;
      }
    }
  }

  return 0;
}/*}}}*/

/**
 * parses RAKIS config from gramine's manifest
 * returns:
 *   - 0 if successful
 *   - 1 if RAKIS should be disabled
 *   - <0 if there is an error
 */
static int parse_config(void){/*{{{*/
  int ret;
  g_rakis_config = calloc(1, sizeof(struct rakis_config));
  if(!g_rakis_config){
    ret = -1;
    goto err_out;
  }

  toml_table_t* manifest_rakis = toml_table_in(g_manifest_root, "rakis");
  if (!manifest_rakis){
    g_rakis_config->status.enabled = false;
    return 1;
  }

  {
    bool temp;
    ret = toml_bool_in(manifest_rakis, "enabled", false,
        &temp);
    if (ret < 0) {
      log_error("Cannot parse 'rakis.enabled'");
      ret = -EINVAL;
      goto err_out;
    }
    g_rakis_config->status.enabled = temp;
    if (!g_rakis_config->status.enabled) {
      return 1;
    }
    g_rakis_config->status.initialized_threads = 0;
    g_rakis_config->status.initialization_done = false;
    g_rakis_config->status.terminatation_flag = false;
    g_rakis_config->status.terminated_threads = 0;
  }

  {
    int64_t temp;
    ret = toml_int_in(manifest_rakis, "net_threads_num", 0, &temp);
    if (ret < 0) {
      log_error("Cannot parse 'rakis.net_threads_num' while it is a required config");
      return -EINVAL;
    }
    if (temp == 0) {
      log_error("'rakis.net_threads_num' cannot be zero");
      return -EINVAL;
    }
    g_rakis_config->net_threads_num = temp;
  }

  toml_array_t* netifs_array = toml_array_in(manifest_rakis, "netifs");
  if (!netifs_array){
    log_error("Cannot parse 'rakis.netifs'");
    ret = -EINVAL;
    goto err_out;
  }

  g_rakis_config->netifs_num  = toml_array_nelem(netifs_array);

  g_rakis_config->netifs_cfg = calloc(g_rakis_config->netifs_num, sizeof(struct rakis_netif_cfg));
  if(!g_rakis_config->netifs_cfg){
    ret = -1;
    goto err_out;
  }

  if (parse_netif_config(netifs_array) < 0) {
    log_error("Error while parsing RAKIS netifs config");
    ret = -EINVAL;
    goto err_out;
  }

  toml_table_t* io_uring_cfg = toml_table_in(manifest_rakis, "io_uring");
  if (!io_uring_cfg){
    log_error("Cannot parse 'rakis.io_uring'");
    ret = -EINVAL;
    goto err_out;
  }

  if (parse_io_uring_config(io_uring_cfg) < 0) {
    log_error("Error while parsing RAKIS ior config");
    ret = -EINVAL;
    goto err_out;
  }

  toml_array_t* arp_array = toml_array_in(manifest_rakis, "arp_table");
  if (!arp_array){
    log_error("Cannot parse 'rakis.arp_table'");
    ret = -EINVAL;
    goto err_out;
  }

  g_rakis_config->arp_table_size  = toml_array_nelem(arp_array);
  g_rakis_config->arp_table = calloc(g_rakis_config->arp_table_size, sizeof(struct rakis_arp_entry));
  if(!g_rakis_config->arp_table){
    ret = -1;
    goto err_out;
  }

  if (parse_arp_table(arp_array) < 0) {
    log_error("Error while parsing RAKIS arp table");
    ret = -EINVAL;
    goto err_out;
  }

  debug_print_rakis_config();
  return 0;
err_out:
  if(g_rakis_config){
    free(g_rakis_config);
  }
  return ret;
}/*}}}*/

static int bookkeep_rakis_regions(struct rakis_pal* rakis_pal){/*{{{*/

#define RAKIS_BOOKKEEP_MMAP_FIXED(PTR, SIZE, COMMENT) \
      {\
        int ret = 0; \
        if ((void*)PTR >= g_pal_public_state->memory_address_start \
            && ((void*)PTR + SIZE) <= g_pal_public_state->memory_address_end) { \
          ret = bkeep_mmap_fixed(PTR, ALLOC_ALIGN_UP(SIZE), PROT_READ | PROT_WRITE, \
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, \
              NULL, 0, COMMENT); \
            if (ret < 0) { \
              log_error("RAKIS Could not bookkeep " COMMENT); \
              return ret; \
            }else{ \
              log_debug("RAKIS Bookkeeped " COMMENT " at %p with size %u", PTR, SIZE); \
            } \
        }\
      }

  // bookkeep XDP memory regions
  for (u32 i = 0; i < g_rakis_config->netifs_num; i++) {
    struct rakis_netif_cfg* rakis_netif_cfg = &g_rakis_config->netifs_cfg[i];
    struct rakis_netif_pal* rakis_netif_pal = &rakis_pal->netifs[i];

    for (u32 j = 0; j < rakis_netif_cfg->xsks_num; j++) {
      struct rakis_xsk_cfg* rakis_xsk_cfg = &rakis_netif_cfg->xsks_cfg[j];
      struct rakis_xsk_pal* rakis_xsk_pal = &rakis_netif_pal->xsks[j];

      RAKIS_BOOKKEEP_MMAP_FIXED(rakis_xsk_pal->umem_area,            rakis_xsk_cfg->umem_size,            "rakis_xsk_umem");
      RAKIS_BOOKKEEP_MMAP_FIXED(rakis_xsk_pal->fill_ring.mmap_addr,  rakis_xsk_pal->fill_ring.mmap_size,  "rakis_xsk_fill_ring");
      RAKIS_BOOKKEEP_MMAP_FIXED(rakis_xsk_pal->compl_ring.mmap_addr, rakis_xsk_pal->compl_ring.mmap_size, "rakis_xsk_compl_ring");
      RAKIS_BOOKKEEP_MMAP_FIXED(rakis_xsk_pal->rx_ring.mmap_addr,    rakis_xsk_pal->rx_ring.mmap_size,    "rakis_xsk_rx_ring");
      RAKIS_BOOKKEEP_MMAP_FIXED(rakis_xsk_pal->tx_ring.mmap_addr,    rakis_xsk_pal->tx_ring.mmap_size,    "rakis_xsk_tx_ring");
    }
  }

  // bookkeep io_uring memory regions
  for (u32 i = 0; i < g_rakis_config->io_urings_cfg.io_urings_num; i++) {
    struct rakis_io_uring_cfg* rakis_io_uring_cfg = &g_rakis_config->io_urings_cfg;
    struct rakis_io_uring_pal* rakis_io_uring_pal = &rakis_pal->io_urings[i];

    u32 sqes_size = rakis_io_uring_cfg->entries_num * sizeof(struct io_uring_sqe);
    RAKIS_BOOKKEEP_MMAP_FIXED(rakis_io_uring_pal->sqring.mmap_addr, rakis_io_uring_pal->sqring.mmap_size,  "rakis_io_uring_sqring");
    RAKIS_BOOKKEEP_MMAP_FIXED(rakis_io_uring_pal->sqring.sqes,      sqes_size,  "rakis_io_uring_sqes");
    RAKIS_BOOKKEEP_MMAP_FIXED(rakis_io_uring_pal->cqring.mmap_addr, rakis_io_uring_pal->cqring.mmap_size,  "rakis_io_uring_cqring");
  }

  log_debug("Bookkeeped all RAKIS memory regions");
  return 0;
}/*}}}*/

noreturn static int monitor_thread_wrapper(void* arg){
  libos_tcb_init();
  set_cur_thread(g_monitor_thread);
  log_setprefix(libos_get_tcb());
  PalRAKISMonitorThreadStart(g_rakis_monitor_pal);
  /* Unreachable. */
}

static int start_monitor_thread(void){
  g_monitor_thread = get_new_internal_thread();
  if (!g_monitor_thread) {
    return -1;
  }

  g_rakis_monitor_pal->ready_flag = false;
  g_rakis_monitor_pal->terminate_flag = false;

  PAL_HANDLE handle = NULL;
  int ret = PalThreadCreate(monitor_thread_wrapper, NULL, &handle);
  if (ret < 0) {
    put_thread(g_monitor_thread);
    g_monitor_thread = NULL;
    return -1;
  }
  g_monitor_thread->pal_handle = handle;

  // wait until the monitor thread is ready
  RAKIS_WAIT_UNTIL_ATOMIC_EQ(&g_rakis_monitor_pal->ready_flag, true);
  RAKIS_SET_ATOMIC(&g_rakis_config->status.initialized_threads, 1);

  return 0;
}

noreturn static int net_thread_wrapper(void* arg){
  libos_tcb_init();

  struct new_net_thread_args* args = arg;
  u16 rakis_thread_id = args->rakis_thread_id;
  struct libos_thread* this_thread = g_rakis_net_threads[args->thread_index];
  struct rakis_xsk** xsks = args->xsks;
  u32 xsks_num = args->num_xsks;
  free(arg);

  set_cur_thread(this_thread);
  log_setprefix(libos_get_tcb());
  rakis_net_thread_main(rakis_thread_id, this_thread, xsks, xsks_num);
  /* Unreachable. */
}

static int start_net_thread(u32 thread_index, struct rakis_xsk** xsks, int num_xsks){
  g_rakis_net_threads[thread_index] = get_new_internal_thread();
  if (!g_rakis_net_threads[thread_index]) {
    return -1;
  }

  struct new_net_thread_args* args = calloc(1, sizeof(struct new_net_thread_args));
  if (!args) {
    return -1;
  }
  args->rakis_thread_id = thread_index;
  args->thread_index = thread_index;
  args->xsks = xsks;
  args->num_xsks = num_xsks;

  PAL_HANDLE handle = NULL;
  int ret = PalThreadCreate(net_thread_wrapper, args, &handle);
  if (ret < 0) {
    put_thread(g_rakis_net_threads[thread_index]);
    g_rakis_net_threads[thread_index] = NULL;
    free(args);
    return -1;
  }
  g_rakis_net_threads[thread_index]->pal_handle = handle;

  return 0;
}

static int start_net_threads(void){
  log_debug("Starting RAKIS network threads");
  u32 threads_count = g_rakis_config->net_threads_num;
  g_rakis_net_threads = calloc(sizeof(struct libos_thread*), threads_count);
  if (!g_rakis_net_threads) {
    return -1;
  }

  u32 xsks_per_thread[g_rakis_config->net_threads_num];
  u32 xsks_count = g_rakis_config->total_xsks_num;
  if (xsks_count < threads_count) {
    xsks_count = threads_count;
  }

  u32 xsks_per_thread_floor = xsks_count / threads_count;
  u32 xsks_remaining = xsks_count % threads_count;
  for (u32 i=0; i < threads_count; i++) {
    xsks_per_thread[i] = xsks_per_thread_floor;
    if (xsks_remaining) {
      xsks_per_thread[i]++;
      xsks_remaining--;
    }
  }

  u32 netif_index = 0;
  u32 xsk_index = 0;
  for (u32 i = 0; i < threads_count; i++) {
    u32 xsks_to_copy = xsks_per_thread[i];
    struct rakis_xsk** thread_xsks = calloc(sizeof(struct rakis_xsk*), xsks_to_copy);
    if (!thread_xsks) {
      return -1;
    }

    for (u32 j = 0; j < xsks_to_copy; j++) {
      struct rakis_netif* netif = &g_rakis_netifs[netif_index];
      u32 xsks_in_netif = netif->xsks_num;

      if (xsk_index < xsks_in_netif) {
        thread_xsks[j] = rakis_xsk_get_xsk(netif->xsks, xsk_index);
        xsk_index++;
      }

      if (xsk_index >= xsks_in_netif) {
        xsk_index = 0;
        netif_index++;
      }

      if (netif_index >= g_rakis_config->netifs_num) {
        netif_index = 0;
      }
    }

    // start the new thread
    if(start_net_thread(i, thread_xsks, xsks_to_copy) < 0){
      free(thread_xsks);
      return -1;
    }
  }

  return 0;
}

int init_rakis(void){/*{{{*/
  int ret;
  if(!g_manifest_root)
    return -1;

  ret = parse_config();
  if(ret < 0)
    return ret;
  else if (ret == 1) // rakis disabled
    return 0; // return 0 so that we do not error out

  // Config is parsed and RAKIS should be enabled.. lets roll!

  struct rakis_pal* rakis_pal = calloc(1, sizeof(struct rakis_pal));
  if (!rakis_pal) {
    return -1;
  }

  rakis_pal->netifs = calloc(g_rakis_config->netifs_num, sizeof(struct rakis_netif_pal));
  if (!rakis_pal->netifs) {
    return -1;
  }

  for (u32 i = 0; i < g_rakis_config->netifs_num; i++) {
    struct rakis_netif_pal* rakis_netif_pal = &rakis_pal->netifs[i];
    rakis_netif_pal->xsks = calloc(g_rakis_config->netifs_cfg[i].xsks_num, sizeof(struct rakis_xsk_pal));
    if (!rakis_netif_pal->xsks) {
      return -1;
    }
  }

  rakis_pal->io_urings = calloc(g_rakis_config->io_urings_cfg.io_urings_num, sizeof(struct rakis_io_uring_pal));
  if (!rakis_pal->io_urings) {
    return -1;
  }

  // do the host Initializations
  ret = PalRAKISInit(g_rakis_config, rakis_pal);
  if(ret < 0){
    goto free_rakis_out;
  }

  // save the rakis monitor pal
  g_rakis_monitor_pal = rakis_pal->rakis_monitor;

  // bookkeep all the memory regions
  ret = bookkeep_rakis_regions(rakis_pal);
  if(ret < 0){
    goto free_rakis_out;
  }

  // initialize the netifs
  ret = rakis_init_netifs(rakis_pal);
  if(ret < 0){
    log_error("Could not initialize RAKIS netifs");
    goto free_rakis_out;
  }

  // start the monitor thread
  ret = start_monitor_thread();
  if(ret < 0){
    log_error("Could not start monitor thread");
    goto free_rakis_out;
  }

  // initialize the network stack
  ret = rakis_stack_init();
  if(ret < 0){
    log_error("Could not initialize RAKIS network stack");
    goto free_rakis_out;
  }

  // start the network threads
  ret = start_net_threads();
  if(ret < 0){
    log_error("Could not start RAKIS network threads");
    goto free_rakis_out;
  }

  // wait until all threads are initialized
  RAKIS_WAIT_UNTIL_ATOMIC_EQ(
      &g_rakis_config->status.initialized_threads,
      g_rakis_config->net_threads_num + 1 // +1 for the monitor thread
  );

  // then mark the initialization as done
  RAKIS_SET_ATOMIC(&g_rakis_config->status.initialization_done, true);

  log_debug("RAKIS initialization done");

  ret = 0;

free_rakis_out:
  // free the rakis pal as we do not need it anymore
  for (u32 i = 0; i < g_rakis_config->netifs_num; i++) {
    free(rakis_pal->netifs[i].xsks);
  }
  free(rakis_pal->netifs);
  free(rakis_pal->io_urings);
  free(rakis_pal);
  rakis_pal = NULL;

  return ret;
}/*}}}*/
