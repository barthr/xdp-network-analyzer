#define __TARGET_ARCH_x86

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "debug.h"
#include "maps.h"

#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

SEC("uprobe/lookup")
int inspect_dns_lookup(struct pt_regs* ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    dns_event ev = {
        .type = INVOKE_RETRIEVE_HOSTNAME,
        .pid = pid,
    };

    bpf_probe_read_user_str(&ev.hostname, sizeof(ev.hostname), (void*)PT_REGS_PARM1(ctx));

    __u32* value = bpf_map_lookup_elem(&hostname_to_pid, &ev.hostname);

    debug_bpf_printk("Got here with pid %d hostname: %s", pid, ev.hostname);

    if (!value) {
        debug_bpf_printk("Hostname not mapped to pid %d: %d", pid, value);
        bpf_map_update_elem(&hostname_to_pid, &ev.hostname, &pid, BPF_NOEXIST);
    } else {
        debug_bpf_printk("Hostname is already mapped to pid %d", pid);
    }

    bpf_ringbuf_output(&dns_events, &ev, sizeof(ev), 0);

    return 0;
}

struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    __u32 ai_addrlen;
    struct sockaddr* ai_addr;
    char* ai_canonname;
    struct addrinfo* ai_next;
};

SEC("uretprobe/response")
int inspect_dns_response(struct pt_regs* ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    dns_event ev = {
        .type = INVOKE_RETRIEVE_HOSTNAME_RETURN,
        .pid = pid,
    };

    bpf_probe_read_user_str(&ev.hostname, sizeof(ev.hostname), (void*)PT_REGS_PARM1(ctx));

    debug_bpf_printk("Got here with pid %d hostname: %s", pid, ev.hostname);

    bpf_ringbuf_output(&dns_events, &ev, sizeof(ev), 0);

    return 0;

    // TODO: return hostname

    // The retval of getaddrinfo() call will be the first addrinfo struct
    // struct addrinfo res;
    // struct addrinfo* res_ptr;
    // struct addrinfo** res = &res_ptr;

    // if (bpf_probe_read_user(res, sizeof(*res), (void*)PT_REGS_PARM4(ctx)) != 0) {
    //     debug_bpf_printk("Test 1");
    //     return 0;
    // } else {
    //     debug_bpf_printk("Test 2");
    // }

    // struct addrinfo res_data;
    // if (bpf_probe_read_user(&res_data, sizeof(res_data), (void*)*res) != 0) {
    //     return 0;
    // }

    // // debug_bpf_printk("Oh noes %s", res.ai_canonname);
    // // // Check the address family
    // if (res_data.ai_family == AF_INET) {
    //     debug_bpf_printk("Yeey");

    //     struct sockaddr_in addr_in;
    //     if (bpf_probe_read_user(&addr_in, sizeof(addr_in), res_data.ai_addr) != 0) {
    //         return 0;
    //     }
    //     debug_bpf_printk("Hoi %d", addr_in.sin_port);
    // }

    // return 0;
}