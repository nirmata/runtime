// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"

struct iphdr {
    __u8  ihl_version;
    __u8  tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
};

// record_ip_event bumps the (daddr, decision) counter. The value is a __u32 --
// looking it up as anything narrower would only ever increment the low byte on
// little-endian, wrapping counts at 255. The add is atomic because cgroup_skb
// programs run concurrently per-CPU and a plain (*val)++ is a lossy
// read-modify-write.
static __always_inline void record_ip_event(__u32 daddr, __u32 decision)
{
    struct ip_event_key key = {};
    key.daddr = daddr;
    key.decision = decision;

    __u32 *val = bpf_map_lookup_elem(&ip_events, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
        return;
    }

    __u32 init_count = 1;
    if (bpf_map_update_elem(&ip_events, &key, &init_count, BPF_NOEXIST) != 0) {
        // lost the create race with another CPU: the entry exists now, add to it
        val = bpf_map_lookup_elem(&ip_events, &key);
        if (val) {
            __sync_fetch_and_add(val, 1);
        }
    }
}

// The program is structured decision -> record -> return: the decision is fully
// computed first, then observed, then returned. No enforcement path may return
// before the observation branch -- that is exactly how default-deny drops used
// to become invisible to monitoring.
SEC("cgroup_skb/egress")
int cgroup_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return 1;

    // read the flags
    __u32 zero_key = 0;
    __u8 *f = bpf_map_lookup_elem(&flags, &zero_key);
    __u32 daddr = ip->daddr;

    // invalid state. it should always be present.
    // 3 is NET_XMIT_CN (transmit with congestion signal), i.e. this fails
    // open. Preserved byte-for-byte; changing the return contract is out of
    // scope here.
    if (f == NULL) {
        return 3;
    };

    // decision: under default deny only allowed_ips passes, otherwise only
    // banned_ips drops
    __u32 decision = DECISION_ALLOW;
    if (*f & (1 << DEFAULT_DENY)) {
        if (bpf_map_lookup_elem(&allowed_ips, &daddr) == NULL) {
            decision = DECISION_DENY;
        }
    } else if (bpf_map_lookup_elem(&banned_ips, &daddr) != NULL) {
        decision = DECISION_DENY;
    }

    // record: learning mode counts every flow, denied ones included
    if (*f & (1 << LEARNING_MODE)) {
        record_ip_event(daddr, decision);
    }

    // return: 1 = pass, 0 = drop
    if (decision == DECISION_DENY) {
        return 0;
    }
    return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
