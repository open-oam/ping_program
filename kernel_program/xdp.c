#include "bpf_helpers.h"

// #include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>

#include <stddef.h>

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))

#define ICMP_PKT_SIZE sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)

#define ICMP_ECHO_LEN 64

struct icmphdr_t {
    __u8 type;
    __u8 code;
    __u16 checksum;
    __u16 id;
    __u16 sequence;
    __u32 orig_time;
    __u32 rec_time;     // Unused
    __u32 trans_time;   // Unused
};

// BPF_MAP_DEF(iface_lookup) = {
//     .map_type = BPF_MAP_TYPE_ARRAY,
//     .key_size = sizeof(__u32),
//     .value_size = sizeof(__u32),
//     .max_entries = 10,  
// };
// BPF_MAP_ADD(iface_lookup);


//Perf event map
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);

//Perf event map value
struct perf_event_item {
    __u16 id;
    __u16 sequence;
    __u32 orig_time;
    __u64 rec_time;
    // __u32 source_ip;
};
_Static_assert(sizeof(struct perf_event_item) == 16, "wrong size of perf_event_item");

//Recomputes an internet checksum
__u16 calc_checksum_diff_u8 (__u16 old_checksum, __u8 old_value, __u8 new_value, __u32 value_offset) {

    if (new_value == old_value)
	    return old_checksum;
    int offset = 8 * (value_offset % 2);

    if (new_value > old_value) {
        int modifier = ((int)new_value - (int)old_value) << offset;
        __u32 checksum = (__u32)old_checksum - modifier;
        checksum = (checksum & 0xffff) + (checksum >> 16);
        return checksum;
    }
    else if (old_value > new_value) {
        int modifier = ((int)old_value - (int)new_value) << offset;
        __u32 checksum = (__u32)old_checksum + modifier;
        checksum = (checksum & 0xffff) + (checksum >> 16);
        return checksum;
    }
    return -1;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    // Set data pointers to context
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    //Verifier check for packet size
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr_t) > data_end)
        return XDP_PASS;

    struct ethhdr *eth_header = data;

    if (eth_header->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip_header = data + sizeof(struct ethhdr);

    if (ip_header->protocol != IPPROTO_ICMP) {
        return XDP_PASS;
    }

    __u64 rec_time = bpf_ktime_get_ns();

    struct icmphdr_t *icmp_header = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (icmp_header->type == ICMP_ECHO) {
        __u8 src_mac[ETH_ALEN];
        __u8 dst_mac[ETH_ALEN];
        memcpy(src_mac, eth_header->h_source, ETH_ALEN);
        memcpy(dst_mac, eth_header->h_dest, ETH_ALEN);

        //Swap MAC addresses
        memcpy(eth_header->h_dest, src_mac, ETH_ALEN);
        memcpy(eth_header->h_source, dst_mac, ETH_ALEN);

        //Get IP addresses
        __u32 src_ip = ip_header->saddr;
        __u32 dst_ip = ip_header->daddr;

        // //Swap IP addresses
        ip_header->saddr = dst_ip;
        ip_header->daddr = src_ip;
	
	ip_header->ttl = 64;

        //Recompute IP checksum and save to context
        
        icmp_header->type = ICMP_ECHOREPLY;
        icmp_header->checksum = calc_checksum_diff_u8(icmp_header->checksum, ICMP_ECHO, ICMP_ECHOREPLY, ICMP_TYPE_OFF);

        // __u32 key = 1;
        // __u32 *ifindex = bpf_map_lookup_elem(&iface_lookup, &key);
        // return bpf_redirect(*ifindex, 0);
        return bpf_redirect(0, 0);

    } else if (icmp_header->type == ICMP_ECHOREPLY) {
        
        struct perf_event_item event = {
            .id = icmp_header->id,
            .sequence = icmp_header->sequence,
            .orig_time = icmp_header->orig_time,
            .rec_time = rec_time,
            // .source_ip = ip_header->saddr,
        };

        __u64 flags = BPF_F_CURRENT_CPU;
        bpf_perf_event_output(ctx, &perfmap, flags, &event, sizeof(event));
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
