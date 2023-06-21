// #include "vmlinux.h"

// #include <bpf/bpf_endian.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <string.h>

// #include "debug.h"
// #include "headers.c"
// #include "maps.h"
// #include "parsers.c"

// char LICENSE[] SEC("license") = "GPL";

// static int __always_inline process_udp_packet(cursor* cursor);
// static int __always_inline process_tcp_packet(cursor* cursor);

// const __u32 DEFAULT_XDP_ACTION = XDP_PASS;

// struct rx_count {
//     __u64 bytes;
//     __u64 packets;
// };

// enum ETH_TYPES {
//     IPV4 = 0x0800,
// };

// enum IP_TYPES {
//     UDP = 0x11,
//     TCP = 0x06,
//     ICMP = 0x01,
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, __u32);
//     __type(value, struct rx_count);
//     __uint(max_entries, 1 << 24);
// } incoming_ip_traffic SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1 << 24);
// } dns_packets SEC(".maps");

// SEC("tc")
// int my_program(struct __sk_buff* skb)
// {
//     struct ethhdr eth_hdr;
//     if (bpf_skb_load_bytes(skb, 0, &eth_hdr, sizeof(eth_hdr)) < 0)
//         return DEFAULT_XDP_ACTION;

//     // The protocol is not IPv4, so we can't parse an IPv4 source address.
//     if (bpf_ntohs(eth_hdr.h_proto) != IPV4)
//         return DEFAULT_XDP_ACTION;

//     __u64 c_group = bpf_skb_cgroup_id(skb);

//     __u8 key = 1;
//     __u64* user_pid = bpf_map_lookup_elem(&pid_monitor_map, &key);

//     if (user_pid && (*user_pid == c_group)) {
//         debug_bpf_printk("eth %d", eth_hdr.h_proto);
//         debug_bpf_printk("cgroup %d", c_group);
//     }

//     // struct iphdr* ip;
//     // if (!(ip = parse_iphdr(&c)))
//     //     return DEFAULT_XDP_ACTION;

//     // // Retrieve IPv4 header fields
//     // __u32 src_ip = ip->saddr;
//     // __u8 protocol = ip->protocol;

//     // struct rx_count* rx = bpf_map_lookup_elem(&incoming_ip_traffic, &src_ip);

//     // if (rx) {
//     //     rx->bytes += packet_size;
//     //     rx->packets++;
//     // } else {
//     //     bpf_map_update_elem(&incoming_ip_traffic, &src_ip, &(struct rx_count) { .bytes = packet_size, .packets = 1 }, BPF_ANY);
//     // }

//     // // Retrieve the rx_count for the ip address in a map
//     // switch (protocol) {
//     // case UDP:
//     //     return process_udp_packet(&c);
//     // case TCP:
//     //     return process_tcp_packet(&c);
//     // default:
//     //     return DEFAULT_XDP_ACTION;
//     // }

//     return DEFAULT_XDP_ACTION;
// }

// static int __always_inline process_udp_packet(cursor* cursor)
// {

//     struct udphdr* udp;
//     if (!(udp = parse_udphdr(cursor)))
//         return DEFAULT_XDP_ACTION;

//     if (udp->source == bpf_htons(53)) {

//         dnshdr* dns;
//         if (!(dns = parse_dnshdr(cursor)))
//             return DEFAULT_XDP_ACTION;

//         // if (dns->qr != 1) {
//         //     return DEFAULT_XDP_ACTION;
//         // }

//         __u64 packet_size = sizeof(dnshdr);

//         // dnshdr dns_to_user_space = {
//         //     .transaction_id = dns->transaction_id,
//         //     // .rd = dns->rd,
//         //     // .tc = dns->tc,
//         //     // .aa = dns->aa,
//         //     // .opcode = dns->opcode,
//         //     // .qr = dns->qr,
//         //     // .rcode = dns->rcode,
//         //     // .cd = dns->cd,
//         //     // .ad = dns->ad,
//         //     // .z = dns->z,
//         //     // .ra = dns->ra,
//         //     // .q_count = dns->q_count,
//         //     // .ans_count = dns->ans_count,
//         //     // .auth_count = dns->auth_count,
//         //     // .add_count = dns->add_count,
//         // };

//         // __u64 packet_size = sizeof(dnshdr);
//         dnshdr dns_to_user_space = *dns;

//         bpf_ringbuf_output(&dns_packets, &dns_to_user_space, packet_size, 0);
//     }

//     return DEFAULT_XDP_ACTION;
// }

// static int __always_inline process_tcp_packet(cursor* cursor)
// {
//     struct tcphdr* tcp;
//     if (!(tcp = parse_tcphdr(cursor)))
//         return DEFAULT_XDP_ACTION;

//     return DEFAULT_XDP_ACTION;
// }