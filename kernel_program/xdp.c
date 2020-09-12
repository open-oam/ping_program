// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// Very simple XDP program for eBPF library integration tests

#include "bpf_helpers.h"
// #include "bpf_h.h"
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
// #include <linux/bpf.h>
#include <linux/if_ether.h>
#include <stddef.h>

#define bpf_memcpy __builtin_memcpy

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

#define ICMP_ECHO_LEN		64



BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);


struct perf_event_item {
  __u32 data;
};
// _Static_assert(sizeof(struct perf_event_item) == 12, "wrong size of perf_event_item");


static __always_inline __u16 csum_fold_helper(__wsum sum) {
	sum = (sum & 0xffff) + (sum >> 16);
	return ~((sum & 0xffff) + (sum >> 16));
}

static __always_inline __u16 ipv4_csum(void *data_start, int data_size ) {
	__wsum sum;

	sum = bpf_csum_diff(0, 0, data_start, data_size, 0);
	return csum_fold_helper(sum);
}


SEC("xdp_prog")
int packet_count(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Only IPv4 supported for this example
  
  if (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
		return XDP_PASS;
  }

  struct ethhdr *eth_header = data;
  struct iphdr *ip_header = data + sizeof(struct ethhdr);
  struct icmphdr *icmp_header = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
 
	if (eth_header->h_proto != __constant_htons(ETH_P_IP)) {
		return XDP_PASS;
  }

	if (ip_header->protocol != IPPROTO_ICMP) {
		return XDP_PASS;
  }

  if (icmp_header->type == ICMP_ECHO) {
    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];

    memcpy(src_mac, eth_header->h_source, ETH_ALEN);
    memcpy(dst_mac, eth_header->h_dest, ETH_ALEN);

    bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_source), dst_mac, ETH_ALEN, 0);
    bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN, 0);

    __u32 src_ip = ip_header->saddr;
    __u32 dst_ip = ip_header->daddr;

    bpf_skb_store_bytes(ctx, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);
    bpf_skb_store_bytes(ctx, IP_DST_OFF, &src_ip, sizeof(src_ip), 0);


    // __u8 new_type = ICMP_ECHOREPLY;
    // bpf_l4_csum_replace(ctx, ICMP_CSUM_OFF, ICMP_ECHO, new_type, ICMP_CSUM_SIZE);
    // bpf_skb_store_bytes(ctx, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0);

    icmp_header->type = ICMP_ECHOREPLY;
    icmp_header->checksum = 0;
    icmp_header->checksum = ipv4_csum(icmp_header, ICMP_ECHO_LEN);

    return XDP_PASS;

  } else if (icmp_header->type == ICMP_ECHOREPLY) {


    struct perf_event_item evt = {
      .data = 0
    };
    // flags for bpf_perf_event_output() actually contain 2 parts (each 32bit long):
    //
    // bits 0-31: either
    // - Just index in eBPF map
    // or
    // - "BPF_F_CURRENT_CPU" kernel will use current CPU_ID as eBPF map index
    //
    // bits 32-63: may be used to tell kernel to amend first N bytes
    // of original packet (ctx) to the end of the data.

    // So total perf event length will be sizeof(evt) + packet_size
    __u64 flags = BPF_F_CURRENT_CPU | (data_end - data << 32);
    bpf_perf_event_output(ctx, &perfmap, flags, &evt, sizeof(evt));
    return XDP_PASS;


  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPLv2";
