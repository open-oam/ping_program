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

// Ethernet header
// struct ethhdr {
//   __u8 h_dest[6];
//   __u8 h_source[6];
//   __u16 h_proto;
// } __attribute__((packed));

// IPv4 header
// struct iphdr {
//   __u8 ihl : 4;
//   __u8 version : 4;
//   __u8 tos;
//   __u16 tot_len;
//   __u16 id;
//   __u16 frag_off;
//   __u8 ttl;
//   __u8 protocol;
//   __u16 check;
//   __u32 saddr;
//   __u32 daddr;
// } __attribute__((packed));



#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

// eBPF map to store IP proto counters (tcp, udp, etc)
BPF_MAP_DEF(protocols) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 255,
};
BPF_MAP_ADD(protocols);

// icmphdr
// XDP program //
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
 
    // from ebpf-icmp-ping github
	if (ether->h_proto != __constant_htons(ETH_P_IP))
		return XDP_PASS;

	/* We handle only ICMP traffic */
	if (ip_header->protocol != IPPROTO_ICMP)
		return XDP_PASS;

	/* ...and only if it is an actual incoming ping */
	// if (icmp_header->type != ICMP_ECHO || ) {
    
    // }

    switch(icmp_header->type) {

    case ICMP_ECHO:

       /* Let's grab the MAC address.
	 * We need to copy them out, as they are 48 bits long */
        __u8 src_mac[ETH_ALEN];
        __u8 dst_mac[ETH_ALEN];
        bpf_memcpy(src_mac, ether->h_source, ETH_ALEN);
        bpf_memcpy(dst_mac, ether->h_dest, ETH_ALEN);

        bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_source), dst_mac, ETH_ALEN, 0);
        bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN, 0);

        /* Let's grab the IP addresses.
	 * They are 32-bit, so it is easy to access */
        __u32 src_ip = ip_header->saddr;
        __u32 dst_ip = ip_header->daddr;

        /* Swap the IP addresses.
        bpf_skb_store_bytes(ctx, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);
        bpf_skb_store_bytes(ctx, IP_DST_OFF, &src_ip, sizeof(src_ip), 0);

            /* Change the type of the ICMP packet to 0 (ICMP Echo Reply).
        * This changes the data, so we need to re-calculate the checksum
        */
        __u8 new_type = ICMP_ECHOREPLY;
        /* We need to pass the full size of the checksum here (2 bytes) */
        bpf_l4_csum_replace(ctx, ICMP_CSUM_OFF, ICMP_ECHO, new_type, ICMP_CSUM_SIZE);
        bpf_skb_store_bytes(ctx, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0);

        return XDP_TX; 

    case ICMP_ECHOREPLY:

    default: /* Optional */
        return XDP_PASS;
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
