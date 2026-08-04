// +build ignore

#define IPPROTO_UDP 17
#define DNS_PORT 53

#define DNS_FLAG_RESPONSE 0x8000
#define DNS_FLAG_RCODE 0x000f
#define DNS_TYPE_A 1


#define MAX_ANSWER_RECORDS 8
#define MAX_OWNER_LABELS 8

struct dnshdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};

struct dns_rr {
    __be16 type;
    __be16 class;
    __be32 ttl;
    __be16 rdlength;
} __attribute__((packed));

// sizeof() is what walks the read cursor past a record header, and the natural
// layout pads this one to 12 for the __be32 -- which lands two bytes into the
// RDATA and reads a mangled address, or none at all off the end of the packet.
_Static_assert(sizeof(struct dns_rr) == 10, "dns_rr must match the wire layout");

// domain_id comes from the question, not from each record's owner name: a CNAME
// chain gives the A record a different owner, and policy names what the pod
// asked for.
static __always_inline void snoop_answers(struct __sk_buff *skb, __u32 off,
                                          __u32 ancount, __u32 domain_id)
{
    struct dns_rr rr;
    __u8 b;

    for (__u32 i = 0; i < MAX_ANSWER_RECORDS; i++) {
        if (i >= ancount)
            return;

        int owner_done = 0;
#pragma unroll
        for (__u32 j = 0; j < MAX_OWNER_LABELS; j++) {
            if (bpf_skb_load_bytes(skb, off, &b, sizeof(b)) < 0)
                return;
            if ((b & DNS_LABEL_PTR) == DNS_LABEL_PTR) {
                off += 2;
                owner_done = 1;
                break;
            }
            if (b & DNS_LABEL_PTR)
                return;
            off += 1 + b;
            if (b == 0) {
                owner_done = 1;
                break;
            }
        }
        if (!owner_done)
            return;

        if (bpf_skb_load_bytes(skb, off, &rr, sizeof(rr)) < 0)
            return;
        off += sizeof(rr);

        __u16 rdlength = bpf_ntohs(rr.rdlength);
        if (bpf_ntohs(rr.type) == DNS_TYPE_A && rdlength == 4) {
            __u32 addr;
            if (bpf_skb_load_bytes(skb, off, &addr, sizeof(addr)) < 0)
                return;
            bpf_map_update_elem(&ip_domain, &addr, &domain_id, BPF_ANY);
        }

        off += rdlength;
    }
}

// Observation only: every path returns 1. A DNS answer this program cannot
// parse must still reach the pod.
SEC("cgroup_skb/ingress")
int cgroup_dns_ingress(struct __sk_buff *skb)
{
    // bpf_skb_load_bytes rather than direct packet access: an ingress skb may
    // be non-linear, and data_end would then cut the answer section off mid-way
    // and silently lose the records.
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0)
        return 1;
    if ((ip.ihl_version >> 4) != 4 || ip.protocol != IPPROTO_UDP)
        return 1;
    if (bpf_ntohs(ip.frag_off) & 0x1fff)
        return 1;

    __u32 ihl = (ip.ihl_version & 0x0f) * 4;
    if (ihl < sizeof(ip))
        return 1;

    __be16 sport;
    if (bpf_skb_load_bytes(skb, ihl, &sport, sizeof(sport)) < 0)
        return 1;
    if (bpf_ntohs(sport) != DNS_PORT)
        return 1;

    __u32 dns_off = ihl + 8;
    struct dnshdr dns;
    if (bpf_skb_load_bytes(skb, dns_off, &dns, sizeof(dns)) < 0)
        return 1;

    __u16 flags = bpf_ntohs(dns.flags);
    if (!(flags & DNS_FLAG_RESPONSE) || (flags & DNS_FLAG_RCODE))
        return 1;
    if (bpf_ntohs(dns.qdcount) != 1)
        return 1;

    __u32 ancount = bpf_ntohs(dns.ancount);
    if (ancount == 0)
        return 1;

    struct domain_key key = {};
    __u32 qname_len = 0;
    if (read_qname(skb, dns_off + sizeof(dns), &key, &qname_len) < 0)
        return 1;

    __u32 *domain_id = bpf_map_lookup_elem(&domain_ids, &key);
    if (!domain_id)
        return 1;

    snoop_answers(skb, dns_off + sizeof(dns) + qname_len + 4, ancount, *domain_id);
    return 1;
}
