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

    // invalid state. it should always be present
    if (f == NULL) {
        bpf_printk("unexpected state\n");
        return 3;
    };

    // check default deny
    if (*f & (1 << DEFAULT_DENY)) {
        __u8 *val = bpf_map_lookup_elem(&allowed_ips, &daddr);
        if (val) {
            bpf_printk("cgroup_egress (allowlist): ALLOWING daddr=%x\n", daddr);
            return 1;
        }  

        bpf_printk("cgroup_egress (allowlist): BLOCKING daddr=%x\n", daddr);
        return 0;
    };

    // check learning mode
    if (*f & (1 << LEARNING_MODE)) {
        __u8 *val = bpf_map_lookup_elem(&ip_events, &daddr);
        if (val) {
            (*val)++;     
        } else {
            __u32 init_count = 1;
            bpf_map_update_elem(&ip_events, &daddr, &init_count, BPF_ANY);
        }
    }

    __u8 *val = bpf_map_lookup_elem(&banned_ips, &daddr);
    if (val) {
        bpf_printk("cgroup_egress: BLOCKING daddr=%x\n", daddr);
        return 0;
    };

    return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
