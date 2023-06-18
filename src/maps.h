#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8); // Fixed key
    __type(value, __u64);
    __uint(max_entries, 1);
} pid_monitor_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[256]);
    __type(value, __u32); // PID
    __uint(max_entries, 2048); // Currently we allow for 2048 entries
} hostname_to_pid SEC(".maps");

typedef enum {
    INVOKE_RETRIEVE_HOSTNAME,
    INVOKE_RETRIEVE_HOSTNAME_RETURN,
    DNS_REQUEST_PACKET,
    DNS_RESPONSE_PACKET
} event_type;

typedef struct {
    event_type type;
    __u32 pid;
    char hostname[256];
} dns_event;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} dns_events SEC(".maps");
