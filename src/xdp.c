#include "vmlinux.h"

#include <string.h>
#include <bpf/bpf_endian.h>
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
    bpf_printk("%s", "Packet received\n");
    return XDP_PASS;
//    void* data = (void*)(long)ctx->data;
//    void* data_end = (void*)(long)ctx->data_end;
//    struct ethhdr* eth = data;
//
//    /* These keep track of the next header type and iterator pointer */
//    struct hdr_cursor nh = {
//        .pos = data
//    };
//
//    if (eth + 1 > data_end)
//        return XDP_DROP;
//
//    char snum[5];
//
//    bpf_printk("%d", bpf_ntohs(eth->h_proto));
//
//    return XDP_PASS;
}