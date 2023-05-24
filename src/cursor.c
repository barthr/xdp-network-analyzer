#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct {
    void* pos;
    void* end;
} cursor;

static __always_inline cursor cursor_init(struct xdp_md* ctx)
{
    return (cursor) {
        .end = (void*)(long)ctx->data_end,
        .pos = (void*)(long)ctx->data
    };
}