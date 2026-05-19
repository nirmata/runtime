// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
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

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *ethernet_hdr = data;
    if ((void *)(ethernet_hdr+1) > data_end) {
        bpf_printk("tc_egress: dropped at eth bounds check\n");
        return TC_ACT_OK;
    }
    if (ethernet_hdr->h_proto != bpf_htons(ETH_P_IP)) {
        bpf_printk("tc_egress: non-IP packet proto=%x\n", bpf_ntohs(ethernet_hdr->h_proto));
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(ethernet_hdr+1);
    if ((void *)(ip + 1) > data_end) {
        bpf_printk("tc_egress: dropped at ip bounds check\n");
        return TC_ACT_OK;
    }

        __u32 daddr = ip->daddr;
    bpf_printk("tc_egress: daddr=%x\n", daddr);

    __u8 *val = bpf_map_lookup_elem(&banned_ips, &daddr);
    bpf_printk("tc_egress: map lookup result=%d\n", val ? 1 : 0);

    if (val) {
        bpf_printk("tc_egress: BLOCKING daddr=%x\n", daddr);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
