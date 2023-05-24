#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct cursor {
    void* pos;
    void* end;
};

static __always_inline void cursor_init(struct cursor* c, struct xdp_md* ctx)
{
    c->end = (void*)(long)ctx->data_end;
    c->pos = (void*)(long)ctx->data;
}