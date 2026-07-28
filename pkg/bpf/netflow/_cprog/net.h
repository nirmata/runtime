#ifndef KYVERNO_RUNTIME_NET_H
#define KYVERNO_RUNTIME_NET_H

#include <linux/bpf.h>

// Minimal on-the-wire header definitions.
//
// These are declared locally rather than pulled from vmlinux.h so this program
// builds with nothing but linux/bpf.h and libbpf's helper headers (the same
// footprint egressfilter/_cprog/probe.c has). Every multi-byte field is kept
// in its wire (big-endian) form and must be read through bpf_ntohs/bpf_ntohl.
//
// Single-byte fields are byte-order independent, which is why ver_ihl is
// declared as one __u8 and split with masks: `ver_ihl >> 4` is the IP version
// and `ver_ihl & 0x0f` the header length in 32-bit words on every host.
// egressfilter's probe.c names the same byte `ihl_version` and assumes a
// 20-byte header; that is wrong for any packet carrying IP options, so the
// programs here compute the L4 offset from IHL instead.

#define IPPROTO_TCP_ 6
#define IPPROTO_UDP_ 17

#define IPV4_MIN_HLEN 20
#define IPV4_MAX_HLEN 60

struct ipv4_hdr {
    __u8 ver_ihl; // high nibble: version, low nibble: header length in words
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

struct ipv6_hdr {
    __be32 ver_tc_flow;
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
} __attribute__((packed));

struct udp_hdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
} __attribute__((packed));

struct tcp_hdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8 doff_res; // high nibble: data offset in 32-bit words
    __u8 flags;
    __be16 window;
    __be16 check;
    __be16 urg_ptr;
} __attribute__((packed));

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_ACK 0x10

// cgroup_skb verdicts. These programs are observation-only: they must return
// PASS on every path, including every error and give-up path, so that adding
// a detector can never drop a packet.
#define CGROUP_SKB_PASS 1

#endif // KYVERNO_RUNTIME_NET_H
