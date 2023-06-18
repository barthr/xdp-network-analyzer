#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "cursor.c"
#include "debug.h"
#include "headers.h"
#include "parsers.c"

char LICENSE[] SEC("license") = "GPL";

const __u32 DEFAULT_XDP_ACTION = XDP_PASS;

enum IP_TYPES {
    UDP = 0x11,
    TCP = 0x06,
    ICMP = 0x01,
};

enum ETH_TYPES {
    IPV4 = 0x0800,
};

#define DNS_QUERY 0
#define DNS_RESPONSE 1
#define MAX_HOSTNAME_SIZE 256

static int process_udp_packet(cursor* cursor);
static void _parse_dns_query(cursor* cursor, struct dnshdr* dns);

SEC("tc")
int my_program(struct __sk_buff* skb)
{
    cursor c = cursor_init_skb(skb);

    struct ethhdr* ethhdr;
    if (!(ethhdr = parse_ethhdr(&c)))
        return DEFAULT_XDP_ACTION;

    if (bpf_ntohs(ethhdr->h_proto) != IPV4)
        return DEFAULT_XDP_ACTION;

    struct iphdr* ip;
    if (!(ip = parse_iphdr(&c)))
        return DEFAULT_XDP_ACTION;

    __u8 protocol = ip->protocol;
    if (protocol != UDP) {
        return DEFAULT_XDP_ACTION;
    }

    return process_udp_packet(&c);
}

static int __always_inline process_udp_packet(cursor* cursor)
{

    struct udphdr* udp;

    if (!(udp = parse_udphdr(cursor)))
        return DEFAULT_XDP_ACTION;

    // We only process dns query and response packets
    if (udp->dest != bpf_htons(53) || udp->source != bpf_htons(53)) {
        return DEFAULT_XDP_ACTION;
    }

    struct dnshdr* dns;
    if (!(dns = parse_dnshdr(cursor)))
        return DEFAULT_XDP_ACTION;

    __u8 qr = dns->flags & (1 << 15);
    if (qr == DNS_QUERY) {
        debug_bpf_printk("QUERY");
        _parse_dns_query(cursor, dns);
        return DEFAULT_XDP_ACTION;
    }

    return DEFAULT_XDP_ACTION;
}

static void __always_inline _parse_dns_query(cursor* cursor, struct dnshdr* dns)
{
    // We expect a question otherwise the packet is malformed
    if (dns->qdcount <= 0) {
        return;
    }

    struct dns_query* dns_query;
    if (!(dns_query = parse_dns_query(cursor)))
        return;

    // Now we parse the hostname
    // Create buffer to hold the hostname
    char hostname[MAX_HOSTNAME_SIZE] = { 0 };

    for (__u32 i = 0; i < MAX_HOSTNAME_SIZE; i++) {
        if (cursor->pos + 1 > cursor->end) {
            debug_bpf_printk("error: boundary of packet exceeded");
            break;
        }

        __u64* length = cursor->pos++;
        if (length == 0) {
            // So the hostname is empty
            break;
        }

        debug_bpf_printk("length %d", length);

        // The hostname format works as follows:
        // integer of length before the next dot
        // then the string
        // repeat
        // so: test.test.com
        // is in protocol the following
        // 4test4test3com
        cursor->pos += *length;
    }

    debug_bpf_printk("test %s", hostname);
}