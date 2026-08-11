// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"

#define ETH_P_IP 0x0800

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

// iphdr needs to be defined first
#include "dns.c"

// The counter is __u32: a narrower lookup would only bump its low byte on
// little-endian and wrap at 255.
static __always_inline void record_ip_event(__u32 daddr, __u32 decision, __u32 domain_id)
{
    struct ip_event_key key = {};
    key.daddr = daddr;
    key.decision = decision;
    key.domain_id = domain_id;

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
            return;
        }
        __u32 stat = EGRESS_STAT_COUNT_MAP_FULL;
        __u64 *v = bpf_map_lookup_elem(&stats, &stat);
        if (v) {
            *v += 1; // per-CPU value, so no atomic
        }
    }
}

// Ordered decision -> record -> return, so no enforcement return can skip the
// observation branch.
SEC("cgroup_skb/egress")
int cgroup_egress(struct __sk_buff *skb)
{
    // we currently only support ipv4
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return 1;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return 1;

    // read the flags
    __u32 zero_key = 0;
    __u8 *f = bpf_map_lookup_elem(&flags, &zero_key);
    __u32 daddr = ip->daddr;

    // invalid state. it should always be present
    if (f == NULL) {
        return 3;
    };

    // 0 means the address never appeared in a snooped A record, so no domain
    // verdict applies and the id is never looked up.
    __u32 domain_id = 0;
    __u32 *id = bpf_map_lookup_elem(&ip_domain, &daddr);
    if (id) {
        domain_id = *id;
    }

    __u32 decision = DECISION_ALLOW;

    // if there's an explicit deny
    if (bpf_map_lookup_elem(&banned_ips, &daddr) != NULL || (domain_id && 
        bpf_map_lookup_elem(&banned_domains, &domain_id))) {
            decision = DECISION_DENY;
    }

    // if DEFAULT_DENY, and that IP/domain is not in the allow list
    if (*f & (1 << DEFAULT_DENY)) {
        if (bpf_map_lookup_elem(&allowed_ips, &daddr) == NULL &&
            !(domain_id && bpf_map_lookup_elem(&allowed_domains, &domain_id))) {
            decision = DECISION_DENY;
        }
    }

    if (*f & (1 << LEARNING_MODE)) {
        record_ip_event(daddr, decision, domain_id);
    }

    // 1 = pass, 0 = drop
    if (decision == DECISION_DENY) {
        return 0;
    }
    return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
