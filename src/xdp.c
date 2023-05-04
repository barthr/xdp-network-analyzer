#include "vmlinux.h"

#include <string.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
long ringbuffer_flags = 0;

// cursor to keep track of current parsing position
struct hdr_cursor {
    void* pos;
};

SEC("xdp")
int my_program(struct xdp_md* ctx)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth;

    /* These keep track of the next header type and iterator pointer */
    struct hdr_cursor nh = {
        .pos = data
    };

    int nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth + 1 > data_end)
        return XDP_DROP;

    if (nh_type != bpf_htons(0x0800))
        return XDP_DROP;

    char eth_proto_str[6];
    sprintf(eth_proto_str, "%d", ntohs(eth->h_proto));

    bpf_printk("eth_proto_str: %s\n", eth_proto_str);

    bpf_ringbuf_output(&events, eth_proto_str, strlen(eth_proto_str) + 1, 0);

    return XDP_PASS;
}