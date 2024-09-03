/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdbool.h>
#include <xdp/xdp_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define XDP_METADATA_SECTION "xdp_metadata"
#define XSK_PROG_VERSION 1

#define DEFAULT_QUEUE_IDS 64
#define IP_FRAG_MAP_MAX 128

#define IP_MF 0x2000 /* Flag: "More Fragments" */
#define IP_OFFSET 0x1FFF /* "Fragment Offset" part */
#define IP_DF 0x4000 /* dont fragment flag */

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
  __uint(max_entries, IP_FRAG_MAP_MAX);
} ip_frags SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
  __uint(max_entries, DEFAULT_QUEUE_IDS);
} xsks_map SEC(".maps");

struct {
  __uint(priority, 20);
  __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xsk_rakis_prog);

volatile int refcnt = 1;

struct hdr_cursor {
  void* ethhdr;
  void* iphdr;
  void* udphdr;
};

/* This is the program for post 5.3 kernels. */
SEC("xdp")
int xsk_rakis_prog(struct xdp_md *ctx)
{
  /* Make sure refcount is referenced by the program */
  if (!refcnt)
    return XDP_PASS;

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct hdr_cursor nh;

  // we start with eth packets
  nh.ethhdr = data;
  int ethhdrsize = sizeof(struct ethhdr);

  // if it is not an eth, pass to kernel
  if (nh.ethhdr + ethhdrsize > data_end)
    goto pass_to_kernel;

  struct ethhdr *eth = nh.ethhdr;
  int eth_type;
  eth_type = eth->h_proto;

  // if it is not an ip, pass to kernel
  if (eth_type != bpf_htons(ETH_P_IP))
    goto pass_to_kernel;

  // advance to iphdr
  nh.iphdr = nh.ethhdr + ethhdrsize;
  int iphdrsize = sizeof(struct iphdr);

  // if its size is not valid, pass to kernel
  if (nh.iphdr + iphdrsize > data_end)
    goto pass_to_kernel;

  struct iphdr *ip = nh.iphdr;
  int ip_prot = ip->protocol;

  // if it is not a udp packet, pass to kernel
  if (ip_prot != IPPROTO_UDP)
    goto pass_to_kernel;

  // now we know it's a udp packet
  // it might be a fragment

  int ipid = bpf_htons(ip->id);
  int off16 = bpf_htons(ip->frag_off);
  int df = off16 & IP_DF;
  bool add_frag_id = false;

  // if df is set, it cannot be a frag
  if (df)
    goto check_udp_port;

  int off = off16 & IP_OFFSET;
  int mf = off16 & IP_MF;

  if (off || mf) {
    // this is a frag
    // is it our first?

    int* seen = bpf_map_lookup_elem(&ip_frags, &ipid);
    if (seen) {
      // we have seen this one before

      // is it our last?
      if (!mf) {
        long del = bpf_map_delete_elem(&ip_frags, &ipid);
        if (del) {
          bpf_printk("Error: Could not delete ebpf map element");
        }
      }

      goto pass_to_rakis;
    }else{
      // we have not seen this one before..
      // if it is not the first frag, pass to kernel
      if (off != 0)
        goto pass_to_kernel;

      // otherwise, flag so that it is added after checking the port
      add_frag_id = true;
    }
  }

check_udp_port:
  nh.udphdr = nh.iphdr + iphdrsize;
  struct udphdr *udp = nh.udphdr;
  int udphdrsize = sizeof(*udp);

  if (nh.udphdr + udphdrsize > data_end)
    goto pass_to_kernel;

  int udp_port = bpf_htons(udp->dest);
  if (udp_port < 0xe000)
    goto pass_to_kernel;

  if (add_frag_id) {
    long add = bpf_map_update_elem(&ip_frags, &ipid, &ipid, BPF_NOEXIST);
    if (add) {
      bpf_printk("Error: Could not add ebpf map element");
    }
  }

pass_to_rakis:
  return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);

pass_to_kernel:
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
__uint(xsk_prog_version, XSK_PROG_VERSION) SEC(XDP_METADATA_SECTION);
