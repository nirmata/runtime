// +build ignore

// Observation only: every path returns 1. A question this program cannot parse
// must still leave the pod.

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

#define IPPROTO_UDP_ 17
#define IPPROTO_TCP_ 6
#define DNS_PORT 53
#define DNS_FLAG_RESPONSE 0x8000

#define IPV4_MIN_HLEN 20
#define IPV4_MAX_HLEN 60
#define IPV6_HLEN 40

struct dns_query_hdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};

struct udp_hdr_ {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
};

// l4_offset returns the byte offset of the transport header, or 0 when this is
// not a UDP datagram worth looking at.
static __always_inline __u32 l4_offset(struct __sk_buff *skb)
{
    __u8 first;
    if (bpf_skb_load_bytes(skb, 0, &first, sizeof(first)) < 0)
        return 0;

    if ((first >> 4) == 4) {
        __u8 proto;
        __be16 frag_off;
        if (bpf_skb_load_bytes(skb, 9, &proto, sizeof(proto)) < 0)
            return 0;
        if (proto != IPPROTO_UDP_)
            return 0;
        // Only the first fragment carries the transport header.
        if (bpf_skb_load_bytes(skb, 6, &frag_off, sizeof(frag_off)) < 0)
            return 0;
        if (bpf_ntohs(frag_off) & 0x1fff)
            return 0;

        __u32 ihl = (__u32)(first & 0x0f) * 4;
        if (ihl < IPV4_MIN_HLEN || ihl > IPV4_MAX_HLEN)
            return 0;
        return ihl;
    }

    if ((first >> 4) == 6) {
        __u8 nexthdr;
        if (bpf_skb_load_bytes(skb, 6, &nexthdr, sizeof(nexthdr)) < 0)
            return 0;
        // An extension header chain is given up on rather than walked.
        if (nexthdr != IPPROTO_UDP_)
            return 0;
        return IPV6_HLEN;
    }

    return 0;
}

SEC("cgroup_skb/egress")
int cgroup_dns_egress(struct __sk_buff *skb)
{
    // The task cgroup is the fallback for an skb with no socket.
    __u64 cgid = bpf_skb_cgroup_id(skb);
    if (cgid == 0)
        cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&cgids, &cgid))
        return 1;

    __u32 l4 = l4_offset(skb);
    if (l4 == 0)
        return 1;

    struct udp_hdr_ udp;
    if (bpf_skb_load_bytes(skb, l4, &udp, sizeof(udp)) < 0)
        return 1;
    if (udp.dest != bpf_htons(DNS_PORT))
        return 1;

    __u32 dns_off = l4 + sizeof(udp);

    struct dns_query_hdr dns;
    if (bpf_skb_load_bytes(skb, dns_off, &dns, sizeof(dns)) < 0)
        return 1;
    if (bpf_ntohs(dns.flags) & DNS_FLAG_RESPONSE)
        return 1;
    if (bpf_ntohs(dns.qdcount) == 0)
        return 1;

    // The name is read straight into the record: a 128-byte stack buffer plus
    // the unrolled read's spill slots does not fit the 512-byte BPF stack.
    struct dns_query_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __u32 stat = STAT_RINGBUF_FULL;
        __u64 *v = bpf_map_lookup_elem(&stats, &stat);
        if (v)
            *v += 1;
        return 1;
    }
    // Recycled ring buffer memory would otherwise carry the previous record's tail.
    __builtin_memset(e, 0, sizeof(*e));
    e->cgroup_id = cgid;

    __u32 name_len = 0;
    if (read_qname(skb, dns_off + sizeof(dns), &e->name, &name_len) < 0) {
        bpf_ringbuf_discard(e, 0);
        __u32 stat = STAT_NAME_UNREADABLE;
        __u64 *v = bpf_map_lookup_elem(&stats, &stat);
        if (v)
            *v += 1;
        return 1;
    }
    e->name_len = name_len;
    bpf_ringbuf_submit(e, 0);

    return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
