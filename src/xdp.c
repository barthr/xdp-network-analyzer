#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#include "headers.c"
#include "parsers.c"

char LICENSE[] SEC("license") = "GPL";

static int __always_inline process_udp_packet(cursor* cursor);
static int __always_inline process_tcp_packet(cursor* cursor);

const __u32 DEFAULT_XDP_ACTION = XDP_PASS;

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
    ICMP = 0x01,
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
    cursor c = cursor_init(ctx);

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    __u64 packet_size = (__u64)(data_end - data);

    struct ethhdr* eth;
    if (!(eth = parse_ethhdr(&c)))
        return DEFAULT_XDP_ACTION;

    // The protocol is not IPv4, so we can't parse an IPv4 source address.
    if (eth->h_proto != bpf_htons(IPV4)) {
        return DEFAULT_XDP_ACTION;
    }

    struct iphdr* ip;
    if (!(ip = parse_iphdr(&c)))
        return DEFAULT_XDP_ACTION;

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

    switch (protocol) {
    case UDP:
        return process_udp_packet(&c);
    case TCP:
        return process_tcp_packet(&c);
    case ICMP:
        return DEFAULT_XDP_ACTION;
    default:
        return XDP_DROP;
    }
}

static int __always_inline process_udp_packet(cursor* cursor)
{

    struct udphdr* udp;
    if (!(udp = parse_udphdr(cursor)))
        return DEFAULT_XDP_ACTION;

    if (udp->source == bpf_htons(53)) {
        struct dnshdr* dns;
        if (!(dns = parse_dnshdr(cursor)))
            return DEFAULT_XDP_ACTION;

        if (dns->qr == bpf_htons(0)) {
            return XDP_DROP;
        }
        return DEFAULT_XDP_ACTION;
    }

    return DEFAULT_XDP_ACTION;
}

static int __always_inline process_tcp_packet(cursor* cursor)
{
    struct tcphdr* tcp;
    if (!(tcp = parse_tcphdr(cursor)))
        return DEFAULT_XDP_ACTION;

    return DEFAULT_XDP_ACTION;
}