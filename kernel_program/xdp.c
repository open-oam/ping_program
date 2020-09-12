// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// Very simple XDP program for eBPF library integration tests

#include "bpf_helpers.h"
// #include <netinet/ip_icmp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
// #include <linux/bpf.h>
#include <linux/if_ether.h>
#include <stddef.h>



#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

SEC("xdp")
int packet_count(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Only IPv4 supported for this example
  
  if (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
		return XDP_PASS;

    struct ethhdr *ether = data;
    struct iphdr *ip_header = data + sizeof(struct ethhdr);
    struct icmphdr *icmp_header = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
 
	if (ether->h_proto != __constant_htons(ETH_P_IP))
		return XDP_PASS;

	if (ip_header->protocol != IPPROTO_ICMP)
		return XDP_PASS;


    if (icmp_header->type == ICMP_ECHO) {

        __u8 src_mac[ETH_ALEN];
        __u8 dst_mac[ETH_ALEN];

        bpf_memcpy(src_mac, ether->h_source, ETH_ALEN);
        bpf_memcpy(dst_mac, ether->h_dest, ETH_ALEN);

        bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_source), dst_mac, ETH_ALEN, 0);
        bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN, 0);

        __u32 src_ip = ip_header->saddr;
        __u32 dst_ip = ip_header->daddr;

        bpf_skb_store_bytes(ctx, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);
        bpf_skb_store_bytes(ctx, IP_DST_OFF, &src_ip, sizeof(src_ip), 0);

 
        __u8 new_type = ICMP_ECHOREPLY;
        bpf_l4_csum_replace(ctx, ICMP_CSUM_OFF, ICMP_ECHO, new_type, ICMP_CSUM_SIZE);
        bpf_skb_store_bytes(ctx, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0);

        return XDP_TX;
    }


//   if (ether->h_proto == 0x08U) {  // htons(ETH_P_IP) -> 0x08U
//     data += sizeof(*ether);
//     struct iphdr *ip = data;
//     if (data + sizeof(*ip) > data_end) {
//       return XDP_ABORTED;
//     }  
//     // Increase counter in "protocols" eBPF map
//     __u32 proto_index = ip->protocol;
//     __u64 *counter = bpf_map_lookup_elem(&protocols, &proto_index);
//     if (counter) {
//       (*counter)++;
//     }
//   }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPLv2";
