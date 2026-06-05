// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} banned_ips SEC(".maps");

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

    __u32 daddr = ip->daddr;
    __u8 *val = bpf_map_lookup_elem(&banned_ips, &daddr);
    if (val) {
        bpf_printk("cgroup_egress: BLOCKING daddr=%x\n", daddr);
        return 0;
    } else {
        bpf_printk("cgroup_egress: ALLOWING daddr=%x\n", daddr);
    };

    return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
