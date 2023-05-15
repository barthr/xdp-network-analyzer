#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

char LICENSE[] SEC("license") = "GPL";

const __u32 DEFAULT_XDP_ACTION = XDP_PASS;

struct dnshdr {
    uint16_t transaction_id;
    uint8_t rd : 1;
    uint8_t tc : 1;
    uint8_t aa : 1;
    uint8_t opcode : 4;
    uint8_t qr : 1;
    uint8_t rcode : 4;
    uint8_t cd : 1;
    uint8_t ad : 1;
    uint8_t z : 1;
    uint8_t ra : 1;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};

struct rx_count {
    __u64 bytes;
    __u64 packets;
};

enum ETH_TYPES {
    IPV4 = 0x0800,
};

enum IP_TYPES {
    UDP = 0x11,
    TCP = 0x06,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct rx_count);
    __uint(max_entries, 1 << 24);
} incoming_ip_traffic SEC(".maps");

SEC("xdp")
int my_program(struct xdp_md* ctx)
{
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    __u64 packet_size = (__u64)(data_end - data);

    // First, parse the ethernet header.
    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) {
        return DEFAULT_XDP_ACTION;
    }

    // The protocol is not IPv4, so we can't parse an IPv4 source address.
    if (eth->h_proto != bpf_htons(IPV4)) {
        return DEFAULT_XDP_ACTION;
    }

    struct iphdr* ip = data + sizeof(struct ethhdr);
    if ((void*)(ip + 1) > data_end) {
        return DEFAULT_XDP_ACTION;
    }

    // Retrieve IPv4 header fields
    __u32 src_ip = ip->saddr;
    __u8 protocol = ip->protocol;

    // Retrieve the rx_count for the ip address in a map
    struct rx_count* rx = bpf_map_lookup_elem(&incoming_ip_traffic, &src_ip);
    if (rx) {
        rx->bytes += packet_size;
        rx->packets++;
    } else {
        bpf_map_update_elem(&incoming_ip_traffic, &src_ip, &(struct rx_count) { .bytes = packet_size, .packets = 1 }, BPF_ANY);
    }

    // Check if data is UDP
    if (protocol != UDP) {
        return DEFAULT_XDP_ACTION;
    }

    struct udphdr* udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void*)(udp + 1) > data_end) {
        return DEFAULT_XDP_ACTION;
    }

    struct dnshdr* dns = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if ((void*)(udp + 1) > data_end) {
        return DEFAULT_XDP_ACTION;
    }

    return XDP_DROP;
}