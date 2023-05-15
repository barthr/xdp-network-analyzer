#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

char LICENSE[] SEC("license") = "GPL";

static int __always_inline process_udp_packet(struct xdp_md* ctx, void* offset);
static int __always_inline process_tcp_packet(struct xdp_md* ctx, void* offset);

const __u32 DEFAULT_XDP_ACTION = XDP_PASS;

struct dnshdr {
    __u16 transaction_id;
    __u8 rd : 1;
    __u8 tc : 1;
    __u8 aa : 1;
    __u8 opcode : 4;
    __u8 qr : 1;
    __u8 rcode : 4;
    __u8 cd : 1;
    __u8 ad : 1;
    __u8 z : 1;
    __u8 ra : 1;
    __u16 q_count;
    __u16 ans_count;
    __u16 auth_count;
    __u16 add_count;
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

    void* next_header = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    // Out of bounds check for the next header
    if ((next_header + 1) > data_end) {
        return DEFAULT_XDP_ACTION;
    }

    // Check if data is UDP
    if (protocol == UDP) {
        return process_udp_packet(ctx, next_header);
    }

    if (protocol == TCP) {
        return process_tcp_packet(ctx, next_header);
    }

    return DEFAULT_XDP_ACTION;
}

static int __always_inline process_udp_packet(struct xdp_md* ctx, void* offset)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    struct udphdr* udp = offset;
    struct dnshdr* dns = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    if ((void*)(dns + 1) > data_end) {
        return DEFAULT_XDP_ACTION;
    }

    if (dns->qr == bpf_htons(0)) {
        bpf_printk("Opcode: %d", bpf_ntohs(dns->opcode));
        return XDP_DROP;
    }
    bpf_printk("Received DNS");

    return DEFAULT_XDP_ACTION;
}

static int __always_inline process_tcp_packet(struct xdp_md* ctx, void* offset)
{
    struct tcphdr* tcp = offset;
    return DEFAULT_XDP_ACTION;
}