#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct data_t {
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
long ringbuffer_flags = 0;

SEC("xdp")
int my_program(struct xdp_md *ctx) {
    __u64 *slot;
    slot = bpf_ringbuf_reserve(&events, sizeof(struct data_t), ringbuffer_flags);
    if (!slot) {
        return XDP_PASS;
    }

    struct data_t *buffer = bpf_ringbuf_buffer(&events, slot);
    *buffer = (struct data_t){
        .dst_port = 24,
    };

    bpf_ringbuf_submit(slot, ringbuffer_flags);

    return XDP_PASS;
}