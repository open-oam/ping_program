#include "bpf_helpers.h"

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>

#include <stddef.h>

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))

#define ICMP_CSUM_SIZE sizeof(__u16)
#define ICMP_PKT_SIZE sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)

#define ICMP_ECHO_LEN 64


struct perf_event_item {
    __u16 id;
    __u16 sequence;
    __u32 orig_time;
    __u64 rec_time;
};

struct icmphdr_timestamp {
    __u8 type;
    __u8 code;
    __u16 checksum;
    __u16 id;
    __u16 sequence;
    __u32 orig_time;
    __u32 rec_time;     // Unused
    __u32 trans_time;   // Unused
};


//Perf event map
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);   // Macro that defines map properly (needs cleaning)


SEC("xdp_prog")
int packet_count(struct xdp_md *ctx) {
    // Set data pointers to context
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    //Verifier check for packet size
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr_timestamp) > data_end)
        return XDP_PASS;

    struct ethhdr *eth_header = data;

    if (eth_header->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip_header = data + sizeof(struct ethhdr);

    if (ip_header->protocol != IPPROTO_ICMP) {
        return XDP_PASS;
    }

    //TODO: Pull current timestamp
    __u64 rec_time = BPF_FUNC_ktime_get_ns;

    struct icmphdr_timestamp *icmp_header = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (icmp_header->type == ICMP_TIMESTAMP) {
        __u8 src_mac[ETH_ALEN];
        __u8 dst_mac[ETH_ALEN];
        memcpy(src_mac, eth_header->h_source, ETH_ALEN);
        memcpy(dst_mac, eth_header->h_dest, ETH_ALEN);

        //Swap MAC addresses
        bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_source), dst_mac, ETH_ALEN, 0);
        bpf_skb_store_bytes(ctx, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN, 0);

        //Get IP addresses
        __u32 src_ip = ip_header->saddr;
        __u32 dst_ip = ip_header->daddr;

        //Swap IP addresses
        bpf_skb_store_bytes(ctx, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);
        bpf_skb_store_bytes(ctx, IP_DST_OFF, &src_ip, sizeof(src_ip), 0);

        //Recompute IP checksum and save to context
        __u8 new_type = ICMP_ECHOREPLY;
        bpf_l4_csum_replace(ctx, ICMP_CSUM_OFF, ICMP_ECHO, new_type, ICMP_CSUM_SIZE);
        bpf_skb_store_bytes(ctx, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0);

        // icmp_header->type = ICMP_TIMESTAMPREPLY;
        // icmp_header->checksum = 0;
        // icmp_header->checksum = ipv4_csum(icmp_header, ICMP_ECHO_LEN);

        //TODO: Send packet back out same interface

        return XDP_PASS;
    } else if (icmp_header->type == ICMP_TIMESTAMPREPLY) {
        
        //TODO: convert big endian to little endian
        struct perf_event_item event = {
            .id = icmp_header->id,
            .sequence = icmp_header->sequence,
            .orig_time = icmp_header->orig_time,
            .rec_time = rec_time,
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
        // __u64 flags = BPF_F_CURRENT_CPU | (data_end - data << 32);
        __u64 flags = 0;
        bpf_perf_event_output(ctx, &perfmap, flags, &event, sizeof(event));
        return XDP_PASS;
    }

    return XDP_PASS;
}

