// +build ignore

// l7peek: cgroup_skb/egress plaintext-L7 peeker.
//
// On the FIRST data segment of a flow it copies up to L7_MAX_DATA bytes of TCP
// payload into a ring buffer record and stops. It does NOT parse HTTP:
// per proposal §2.3 item 4 the request line and headers are parsed in
// USERSPACE (pkg/bpf/l7peek/decode.go, via net/textproto), because the
// verifier cost of an in-kernel HTTP parser is not worth it and because
// userspace is where the redaction chokepoint (runtimeevent.NewHTTPFacts)
// lives. The kernel must never make a decision that depends on a header value.
//
// Deliberate limits:
//   - Payloads that begin like a TLS record (0x16 0x03) are skipped; those
//     flows belong to tlspeek.
//   - Only the first data segment is copied. A request whose head spans
//     segments is reported truncated; the decoder tolerates truncated headers.
//   - The copy uses bpf_skb_load_bytes rather than per-byte direct packet
//     access on purpose: a 2KB payload routinely lives outside the skb's
//     linear area (direct packet access would simply fail past data_end,
//     losing the whole request), and a 2048 iteration unrolled copy is a
//     needlessly large program. Fixed-offset HEADER reads below still use
//     direct packet access with explicit data_end checks.
//   - pid/comm are hints only: they are the CURRENT task, which is the sending
//     task only in process context. cgroup_id is the attribution key.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define L7PEEK_PASS 1

#define L7_MAX_DATA 2048
#define MAX_COMM_LEN 16

#define IPPROTO_TCP_ 6

struct lp_iphdr {
    __u8 ihl_version;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
};

struct lp_ipv6hdr {
    __u8 priority_version;
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
};

struct lp_tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8 doff_res; /* data offset in the high nibble */
    __u8 flags;
    __be16 window;
    __be16 check;
    __be16 urg_ptr;
};

// http_event MUST stay byte-for-byte identical to l7peek.DecodeHTTPEvent's
// layout in decode.go: 8 + 4 + 2 + 2 + 16 + 1 + 16 + 2048 = 2097 bytes of
// fields with no interior padding (every field after daddr is byte aligned).
// The compiler pads the tail to 2104 for cgroup_id's alignment; the decoder
// tolerates trailing bytes AND records truncated to header + data_len.
struct http_event {
    __u64 cgroup_id;
    __u32 pid;
    __u16 dport;
    __u16 data_len;
    __u8 daddr[16];
    __u8 ipver;
    __u8 comm[MAX_COMM_LEN];
    __u8 data[L7_MAX_DATA];
};

// cgids selects which cgroups produce events (same pattern as
// pkg/bpf/lsm/_cprog/lsm.bpf.c). Filtering in the kernel is mandatory here:
// 2KB per flow node-wide would melt the ring buffer.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgids SEC(".maps");

struct flow_key {
    __u64 cgid;
    __u8 daddr[16];
    __u16 dport;
    __u16 pad0;
    __u32 pad1;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, __u8);
} seen_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

static __always_inline int l4_offset(void *data, void *data_end, __u8 daddr[16], __u8 *ipver)
{
    if (data + 1 > data_end)
        return -1;
    __u8 ver = (*(volatile __u8 *)data) >> 4;

    if (ver == 4) {
        struct lp_iphdr *ip = data;
        if ((void *)(ip + 1) > data_end)
            return -1;
        if (ip->protocol != IPPROTO_TCP_)
            return -1;
        __u32 ihl = (ip->ihl_version & 0x0f) * 4;
        if (ihl < sizeof(struct lp_iphdr))
            return -1;
        daddr[10] = 0xff;
        daddr[11] = 0xff;
        __builtin_memcpy(&daddr[12], &ip->daddr, 4);
        *ipver = 4;
        return (int)ihl;
    }
    if (ver == 6) {
        struct lp_ipv6hdr *ip6 = data;
        if ((void *)(ip6 + 1) > data_end)
            return -1;
        if (ip6->nexthdr != IPPROTO_TCP_)
            return -1;
        __builtin_memcpy(daddr, ip6->daddr, 16);
        *ipver = 6;
        return (int)sizeof(struct lp_ipv6hdr);
    }
    return -1;
}

SEC("cgroup_skb/egress")
int l7_peek(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u64 cgid = bpf_skb_cgroup_id(skb);
    if (cgid == 0)
        cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&cgids, &cgid))
        return L7PEEK_PASS;

    __u8 daddr[16] = {};
    __u8 ipver = 0;
    int ip_len = l4_offset(data, data_end, daddr, &ipver);
    if (ip_len < 0)
        return L7PEEK_PASS;

    struct lp_tcphdr *tcp = data + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return L7PEEK_PASS;
    __u32 doff = (tcp->doff_res >> 4) * 4;
    if (doff < sizeof(struct lp_tcphdr))
        return L7PEEK_PASS;
    __u16 dport = bpf_ntohs(tcp->dest);

    __u32 payload_off = (__u32)ip_len + doff;
    if (payload_off > skb->len)
        return L7PEEK_PASS;
    __u32 payload_len = skb->len - payload_off;
    if (payload_len == 0)
        return L7PEEK_PASS; /* pure ACK / handshake */

    /* Skip anything that looks like a TLS record: that is tlspeek's job. Two
     * fixed-offset direct packet reads with explicit data_end checks. */
    void *payload = (void *)tcp + doff;
    if (payload + 2 <= data_end) {
        __u8 b0 = *(volatile __u8 *)payload;
        __u8 b1 = *(volatile __u8 *)(payload + 1);
        if (b0 == 0x16 && b1 == 0x03)
            return L7PEEK_PASS;
    }

    struct flow_key fk = {};
    fk.cgid = cgid;
    fk.dport = dport;
    __builtin_memcpy(fk.daddr, daddr, 16);
    if (bpf_map_lookup_elem(&seen_flows, &fk))
        return L7PEEK_PASS;

    /* Clamp to the destination array. The mask keeps the length a verifiable
     * scalar for bpf_skb_load_bytes; the explicit compare keeps the intent
     * readable and survives a change to L7_MAX_DATA that is not a power of 2. */
    __u32 copy_len = payload_len;
    if (copy_len > L7_MAX_DATA)
        copy_len = L7_MAX_DATA;
    copy_len &= (L7_MAX_DATA - 1);
    if (copy_len == 0)
        copy_len = L7_MAX_DATA; /* exactly L7_MAX_DATA bytes available */

    struct http_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        __u8 one = 1;
        bpf_map_update_elem(&seen_flows, &fk, &one, BPF_ANY);
        return L7PEEK_PASS;
    }
    /* Reserved ring buffer memory is NOT zeroed. */
    __builtin_memset(ev, 0, sizeof(*ev));

    if (bpf_skb_load_bytes(skb, payload_off, ev->data, copy_len) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return L7PEEK_PASS;
    }

    ev->cgroup_id = cgid;
    ev->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    ev->dport = dport;
    ev->data_len = (__u16)copy_len;
    ev->ipver = ipver;
    __builtin_memcpy(ev->daddr, daddr, 16);
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);

    __u8 one = 1;
    bpf_map_update_elem(&seen_flows, &fk, &one, BPF_ANY);
    return L7PEEK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
