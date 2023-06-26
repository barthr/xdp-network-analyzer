#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "cursor.c"
#include "debug.h"
#include "headers.h"
#include "maps.h"
#include "parsers.c"

char LICENSE[] SEC("license") = "GPL";

const __u32 DEFAULT_XDP_ACTION = XDP_PASS;

#define IPV4 0x0800
#define min(a, b) ((a) < (b) ? (a) : (b))
#define TC_PASS 0
#define UDP 17
#define DNS_QUERY 0
#define DNS_RESPONSE 1
#define MAX_HOSTNAME_SIZE 255

static int process_udp_packet(cursor* cursor);
static void _parse_dns_query(cursor* cursor, struct dnshdr* dns);

SEC("tc")
int my_program(struct __sk_buff* skb)
{
    cursor c = cursor_init_skb(skb);

    struct ethhdr* ethhdr;
    if (!(ethhdr = parse_ethhdr(&c)))
        return TC_PASS;

    if (bpf_ntohs(ethhdr->h_proto) != IPV4) {
        return TC_PASS;
    }

    struct iphdr* ip;
    if (!(ip = parse_iphdr(&c))) {
        return TC_PASS;
    }

    __u8 protocol = ip->protocol;
    if (protocol != UDP) {
        return TC_PASS;
    }

    return process_udp_packet(&c);
}

static int __always_inline process_udp_packet(cursor* cursor)
{

    struct udphdr* udp;

    if (!(udp = parse_udphdr(cursor))) {
        return TC_PASS;
    }

    // We only process dns egress query packets (for now)
    if (bpf_ntohs(udp->dest) != 53) {
        return TC_PASS;
    }

    struct dnshdr* dns;
    if (!(dns = parse_dnshdr(cursor))) {
        return TC_PASS;
    }

    if (dns->opcode == DNS_QUERY) {
        _parse_dns_query(cursor, dns);
        return TC_PASS;
    }

    return TC_PASS;
}

static void __always_inline _parse_dns_query(cursor* cursor, struct dnshdr* dns)
{
    // We expect a question otherwise the packet is malformed
    if (dns->qdcount <= 0) {
        return;
    }
#define check_packet_boundary                                   \
    if (cursor->pos + 1 > cursor->end) {                        \
        debug_bpf_printk("error: boundary of packet exceeded"); \
        return;                                                 \
    }

    char hostname[MAX_HOSTNAME_SIZE] = { 0 };
    check_packet_boundary;

    __u32 domain_part_length = *(char*)(cursor->pos++);
    for (__u32 i = 0; i < MAX_HOSTNAME_SIZE; i++) {
        check_packet_boundary;
        if (*(char*)(cursor->pos) == 0) {
            hostname[i + 1] = '\0';
            debug_bpf_printk("hostname: %s", hostname);
            return;
        }
        char ch = *(char*)(cursor->pos++);
        if (domain_part_length == 0) {
            domain_part_length = ch;
            hostname[i] = '.';
        } else {
            domain_part_length--;
            hostname[i] = ch;
        }
    }

    // if (value) {
    //     //
    // }
    // if (!value) {
    //     debug_bpf_printk("Hostname not found %s", hostname);
    //     // Send event for the given hostname
    //     // We also need to store the tx id in the map so we can correlate the response
    // } else {
    //     debug_bpf_printk("value %d", value);
    // }
    // The next part is the actual DNS query(without hostname) struct dns_query* dnsq;
    // if (!(dnsq = parse_dns_query(cursor))) {
    //     return;
    // }

    // Lookup hostname in

    // Do something with it!?
}