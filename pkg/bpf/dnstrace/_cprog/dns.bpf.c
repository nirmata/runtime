// +build ignore

// dns.bpf.c — observation-only DNS query tracer.
//
// Attach: cgroup_skb/egress, the attach point already proven by
// pkg/bpf/egressfilter (see egressfilter.go's link.AttachCgroup). skb->data
// points at the network header there, so there is no ethernet header to skip.
//
// Filter (kernel side, per proposal §2.3): the cgroup id must be present in the
// `cgids` map. Pods that no policy selected therefore produce zero ring buffer
// traffic; a node-wide firehose of every packet is what this avoids.
//
// Scope: UDP/53 queries only, IPv4 and IPv6. Deliberately NOT handled:
//   - DNS over TCP/53 (needs the 2-byte length prefix and cross-segment
//     reassembly);
//   - IPv6 extension headers (we give up rather than walk the chain);
//   - IPv4 fragments other than the first (no L4 header to parse);
//   - responses (only questions are interesting for shadow-AI detection).
// Every one of those paths returns PASS without emitting.
//
// Verifier notes: the QNAME copy is a single #pragma unroll'd loop with a
// data_end check before every byte read, and the qtype is read with constant
// offsets at the point the root label is found, so no variable-offset packet
// read is ever needed.

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "net.h"

#define DNS_PORT 53
#define DNS_FLAG_QR 0x8000 // set on responses

struct dns_hdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __attribute__((packed));

SEC("cgroup_skb/egress")
int dns_egress(struct __sk_buff *skb)
{
    // bpf_skb_cgroup_id is the socket's cgroup, which stays correct even when
    // the skb is transmitted from softirq context. It returns 0 when the skb
    // has no socket (or the kernel lacks CONFIG_SOCK_CGROUP_DATA), so fall back
    // to the current task's cgroup — DNS is sent from process context.
    __u64 cgid = bpf_skb_cgroup_id(skb);
    if (cgid == 0) {
        cgid = bpf_get_current_cgroup_id();
    }
    if (!bpf_map_lookup_elem(&cgids, &cgid)) {
        return CGROUP_SKB_PASS;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if ((void *)((__u8 *)data + 1) > data_end) {
        return CGROUP_SKB_PASS;
    }

    void *l4 = 0;
    __u8 version = *(__u8 *)data >> 4;

    if (version == 4) {
        struct ipv4_hdr *ip = data;
        if ((void *)(ip + 1) > data_end) {
            return CGROUP_SKB_PASS;
        }
        if (ip->protocol != IPPROTO_UDP_) {
            return CGROUP_SKB_PASS;
        }
        // Only the first fragment carries the UDP header.
        if (bpf_ntohs(ip->frag_off) & 0x1fff) {
            return CGROUP_SKB_PASS;
        }
        __u32 ihl = (__u32)(ip->ver_ihl & 0x0f) * 4;
        if (ihl < IPV4_MIN_HLEN || ihl > IPV4_MAX_HLEN) {
            return CGROUP_SKB_PASS;
        }
        l4 = (__u8 *)data + ihl;
    } else if (version == 6) {
        struct ipv6_hdr *ip6 = data;
        if ((void *)(ip6 + 1) > data_end) {
            return CGROUP_SKB_PASS;
        }
        if (ip6->nexthdr != IPPROTO_UDP_) {
            return CGROUP_SKB_PASS;
        }
        l4 = (__u8 *)data + sizeof(struct ipv6_hdr);
    } else {
        return CGROUP_SKB_PASS;
    }

    struct udp_hdr *udp = l4;
    if ((void *)(udp + 1) > data_end) {
        return CGROUP_SKB_PASS;
    }
    if (udp->dest != bpf_htons(DNS_PORT)) {
        return CGROUP_SKB_PASS;
    }

    struct dns_hdr *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end) {
        return CGROUP_SKB_PASS;
    }
    if (bpf_ntohs(dns->flags) & DNS_FLAG_QR) {
        return CGROUP_SKB_PASS; // a response, not a query
    }
    if (bpf_ntohs(dns->qdcount) == 0) {
        return CGROUP_SKB_PASS;
    }

    struct dns_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return CGROUP_SKB_PASS; // buffer full: lose the observation, not the packet
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->cgroup_id = cgid;
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u8 *q = (__u8 *)(dns + 1);
    int complete = 0;

#pragma unroll
    for (int i = 0; i < MAX_QNAME; i++) {
        if ((void *)(q + i + 1) > data_end) {
            break; // name runs past the packet
        }
        __u8 c = q[i];
        if (c == 0) {
            // Root label: the question type follows immediately. Read it with
            // constant offsets while i is still a compile-time constant.
            if ((void *)(q + i + 3) > data_end) {
                break; // no room for qtype
            }
            e->qtype = ((__u16)q[i + 1] << 8) | (__u16)q[i + 2];
            e->qname_len = (__u16)i;
            complete = 1;
            break;
        }
        e->qname[i] = c;
    }

    if (!complete) {
        // Truncated, oversized (> MAX_QNAME) or qtype-less question. Userspace
        // would only reject it, so drop it here.
        bpf_ringbuf_discard(e, 0);
        return CGROUP_SKB_PASS;
    }

    bpf_ringbuf_submit(e, 0);
    return CGROUP_SKB_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
