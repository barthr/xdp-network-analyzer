#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct event_data {
    char* message;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8000);
} ringbuf_map SEC(".maps");

SEC("xdp")
int my_program(struct xdp_md* ctx)
{
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    // First, parse the ethernet header.
    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) {
        bpf_printk("%s", "Packet dropped");
        return XDP_DROP;
    }

    if (eth->h_proto != bpf_htons(0x0800)) {
        bpf_printk("%s protocol: %d", "ETH Packet dropped", eth->h_proto);
        // The protocol is not IPv4, so we can't parse an IPv4 source address.
        return XDP_DROP;
    }

    struct iphdr* ip = data + sizeof(struct ethhdr);
    if ((void*)(ip + 1) > data_end) {
        bpf_printk("%s", "IP Packet dropped");
        return XDP_DROP;
    }

    // Parse IPv4 header fields
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;

    bpf_printk("%s - %d", "Received IPv4 packet", protocol);

    return XDP_PASS;
}