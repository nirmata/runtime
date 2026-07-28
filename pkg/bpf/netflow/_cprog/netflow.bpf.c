// +build ignore

// netflow.bpf.c — observation-only egress connection tracer.
//
// Attach: cgroup_skb/egress, the attach point already proven by
// pkg/bpf/egressfilter (see egressfilter.go's link.AttachCgroup). skb->data
// points at the network header there, so there is no ethernet header to skip.
//
// Filter (kernel side, per proposal §2.3): the cgroup id must be present in the
// `cgids` map, and a given (cgid, daddr, dport, proto) is reported at most once
// per FLOW_TTL_NS. That is what keeps this from becoming a per-packet firehose.
//
// Emission points:
//   - TCP: the SYN that opens the connection (SYN set, ACK clear).
//   - UDP: the first datagram to a destination in the dedupe window; UDP has no
//     handshake, so first-sight is the only "connection" signal available.
//
// Deliberately NOT handled (all return PASS without emitting): IPv6 extension
// header chains, IPv4 fragments after the first, protocols other than TCP/UDP.
//
// Unlike egressfilter/_cprog/probe.c this computes the L4 offset from the IPv4
// IHL field instead of assuming a 20-byte header, so packets carrying IP
// options are parsed correctly rather than mis-read.

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "net.h"

SEC("cgroup_skb/egress")
int flow_egress(struct __sk_buff *skb)
{
    // bpf_skb_cgroup_id is the socket's cgroup, which stays correct even when
    // the skb is transmitted from softirq context (TCP SYN retransmits). It
    // returns 0 when the skb has no socket, so fall back to the current task.
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

    struct flow_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.cgroup_id = cgid;

    __u8 saddr[ADDR_LEN] = {};
    void *l4 = 0;
    __u8 version = *(__u8 *)data >> 4;

    if (version == 4) {
        struct ipv4_hdr *ip = data;
        if ((void *)(ip + 1) > data_end) {
            return CGROUP_SKB_PASS;
        }
        if (ip->protocol != IPPROTO_TCP_ && ip->protocol != IPPROTO_UDP_) {
            return CGROUP_SKB_PASS;
        }
        // Only the first fragment carries the L4 header.
        if (bpf_ntohs(ip->frag_off) & 0x1fff) {
            return CGROUP_SKB_PASS;
        }
        __u32 ihl = (__u32)(ip->ver_ihl & 0x0f) * 4;
        if (ihl < IPV4_MIN_HLEN || ihl > IPV4_MAX_HLEN) {
            return CGROUP_SKB_PASS;
        }
        __builtin_memcpy(saddr, &ip->saddr, 4);
        __builtin_memcpy(key.daddr, &ip->daddr, 4);
        key.proto = ip->protocol;
        key.ip_ver = 4;
        l4 = (__u8 *)data + ihl;
    } else if (version == 6) {
        struct ipv6_hdr *ip6 = data;
        if ((void *)(ip6 + 1) > data_end) {
            return CGROUP_SKB_PASS;
        }
        if (ip6->nexthdr != IPPROTO_TCP_ && ip6->nexthdr != IPPROTO_UDP_) {
            return CGROUP_SKB_PASS; // extension header chain: give up
        }
        __builtin_memcpy(saddr, ip6->saddr, ADDR_LEN);
        __builtin_memcpy(key.daddr, ip6->daddr, ADDR_LEN);
        key.proto = ip6->nexthdr;
        key.ip_ver = 6;
        l4 = (__u8 *)data + sizeof(struct ipv6_hdr);
    } else {
        return CGROUP_SKB_PASS;
    }

    if (key.proto == IPPROTO_TCP_) {
        struct tcp_hdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            return CGROUP_SKB_PASS;
        }
        // Only the connection-opening SYN. Everything else on the flow —
        // including the SYN-ACK direction, data and teardown — is noise here.
        if (!(tcp->flags & TCP_FLAG_SYN) || (tcp->flags & TCP_FLAG_ACK)) {
            return CGROUP_SKB_PASS;
        }
        key.dport = bpf_ntohs(tcp->dest);
    } else {
        struct udp_hdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            return CGROUP_SKB_PASS;
        }
        key.dport = bpf_ntohs(udp->dest);
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&seen_flows, &key);
    if (last && now >= *last && (now - *last) < FLOW_TTL_NS) {
        return CGROUP_SKB_PASS; // already reported inside the window
    }
    bpf_map_update_elem(&seen_flows, &key, &now, BPF_ANY);

    struct flow_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return CGROUP_SKB_PASS; // buffer full: lose the observation, not the packet
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->cgroup_id = cgid;
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __builtin_memcpy(e->saddr, saddr, ADDR_LEN);
    __builtin_memcpy(e->daddr, key.daddr, ADDR_LEN);
    e->dport = key.dport;
    e->proto = key.proto;
    e->ip_ver = key.ip_ver;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return CGROUP_SKB_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
