// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

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

struct ipv6hdr {
    __u8 priority_version;
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
};

struct tcphdr_prefix {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8   doff_res; /* data offset in the high nibble */
};

static __always_inline int load_u8(struct __sk_buff *skb, __u32 off, __u8 *v)
{
    return bpf_skb_load_bytes(skb, off, v, 1);
}

static __always_inline int load_u16be(struct __sk_buff *skb, __u32 off, __u16 *v)
{
    __u8 b[2];
    if (bpf_skb_load_bytes(skb, off, b, 2) < 0)
        return -1;
    *v = ((__u16)b[0] << 8) | b[1];
    return 0;
}

// The counter is __u32: a narrower lookup would only bump its low byte on
// little-endian and wrap at 255.
static __always_inline void record_proto_event(const struct proto_key *pk, __u32 decision)
{
    struct proto_event_key key = {};
    key.proto = pk->proto;
    __builtin_memcpy(key.alpn, pk->alpn, ALPN_MAX_LEN);
    key.decision = decision;

    __u32 *val = bpf_map_lookup_elem(&proto_events, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
        return;
    }

    __u32 init_count = 1;
    if (bpf_map_update_elem(&proto_events, &key, &init_count, BPF_NOEXIST) != 0) {
        // lost the create race with another CPU: the entry exists now, add to it
        val = bpf_map_lookup_elem(&proto_events, &key);
        if (val) {
            __sync_fetch_and_add(val, 1);
        }
    }
}

/* {proto, ""} in a policy map means "this proto with any ALPN". */
static __always_inline int proto_match(void *map, const struct proto_key *pk)
{
    if (bpf_map_lookup_elem(map, (void *)pk))
        return 1;
    if (pk->alpn[0] == 0)
        return 0;
    struct proto_key wild = {};
    wild.proto = pk->proto;
    return bpf_map_lookup_elem(map, &wild) != NULL;
}

// Ordered decision -> record -> cache -> return, so no enforcement return can
// skip the observation branch. Runs once per flow, at classification; later
// packets take the cached verdict without re-recording.
static __always_inline int settle(struct flow_key *fk, __u32 proto, const char *alpn)
{
    __u32 zero_key = 0;
    __u8 *f = bpf_map_lookup_elem(&flags, &zero_key);

    // invalid state. it should always be present
    if (f == NULL) {
        return 3;
    }

    struct proto_key pk = {};
    pk.proto = proto;
    __builtin_memcpy(pk.alpn, alpn, ALPN_MAX_LEN);

    __u32 decision = DECISION_ALLOW;
    if (*f & (1 << DEFAULT_DENY)) {
        if (!proto_match(&allowed_protos, &pk)) {
            decision = DECISION_DENY;
        }
    } else if (proto_match(&banned_protos, &pk)) {
        decision = DECISION_DENY;
    }

    if (*f & (1 << LEARNING_MODE)) {
        record_proto_event(&pk, decision);
    }

    struct flow_state st = {};
    st.proto = proto;
    __builtin_memcpy(st.alpn, alpn, ALPN_MAX_LEN);
    st.decision = decision;
    bpf_map_update_elem(&flows, fk, &st, BPF_ANY);

    // 1 = pass, 0 = drop
    if (decision == DECISION_DENY) {
        return 0;
    }
    return 1;
}

static __always_inline int cached_verdict(const struct flow_state *st)
{
    return st->decision == DECISION_DENY ? 0 : 1;
}

static __always_inline __u32 parse_client_hello(struct __sk_buff *skb, __u32 base,
                                                __u32 record_end, char *alpn)
{
    __u8 b8;
    __u16 b16;

    if (load_u8(skb, base + 5, &b8) < 0 || b8 != 0x01)
        return PROTO_UNKNOWN;

    /* handshake header(4) + client_version(2) + random(32) */
    __u32 off = 5 + 4 + 2 + 32;

    if (off + 1 > record_end || load_u8(skb, base + off, &b8) < 0)
        return PROTO_UNKNOWN;
    off += 1 + b8; /* session_id */

    if (off + 2 > record_end || load_u16be(skb, base + off, &b16) < 0)
        return PROTO_UNKNOWN;
    off += 2 + b16; /* cipher_suites */

    if (off + 1 > record_end || load_u8(skb, base + off, &b8) < 0)
        return PROTO_UNKNOWN;
    off += 1 + b8; /* compression_methods */

    if (off + 2 > record_end || load_u16be(skb, base + off, &b16) < 0)
        return PROTO_UNKNOWN;
    off += 2;
    __u32 ext_end = off + b16;
    if (ext_end > record_end)
        return PROTO_UNKNOWN;

    for (int i = 0; i < 32; i++) {
        if (off + 4 > ext_end)
            break;
        __u16 ext_type, ext_len;
        if (load_u16be(skb, base + off, &ext_type) < 0 ||
            load_u16be(skb, base + off + 2, &ext_len) < 0)
            return PROTO_UNKNOWN;
        off += 4;
        if (off + ext_len > ext_end)
            return PROTO_UNKNOWN;
        if (ext_type != 16) {
            off += ext_len;
            continue;
        }

        /* ALPN: list length(2), then the first entry: length(1) + bytes */
        if (ext_len < 3 || load_u8(skb, base + off + 2, &b8) < 0)
            return PROTO_UNKNOWN;
        __u32 alen = b8;
        if (3 + alen > ext_len)
            return PROTO_UNKNOWN;
        /* checked last so the verifier carries alen's unsigned [1,16] bounds
         * into the variable-length load: a branch on a register derived from
         * alen would sync away the range the helper call is checked against */
        if (alen == 0 || alen > ALPN_MAX_LEN)
            return PROTO_TLS; /* an entry the policy grammar cannot name: bare tls */

        __u8 tmp[ALPN_MAX_LEN] = {};
        if (bpf_skb_load_bytes(skb, base + off + 3, tmp, alen) < 0)
            return PROTO_UNKNOWN;
        for (int j = 0; j < ALPN_MAX_LEN; j++) {
            if (j >= alen)
                break;
            if (tmp[j] < 0x21 || tmp[j] > 0x7e)
                return PROTO_TLS;
        }
        __builtin_memcpy(alpn, tmp, ALPN_MAX_LEN);
        return PROTO_TLS;
    }

    return PROTO_TLS; /* no ALPN extension: matches the bare tls token */
}

static __always_inline int method_eq(const __u8 *buf, __u32 n, const char *m, __u32 len)
{
    if (n < len + 1)
        return 0;
    for (__u32 i = 0; i < len; i++)
        if (buf[i] != (__u8)m[i])
            return 0;
    return buf[len] == ' ';
}

static __always_inline __u32 classify_tcp(struct __sk_buff *skb, __u32 payload_off,
                                          __u32 payload_len, char *alpn)
{
    __u8 buf[24] = {};
    /* The verifier cannot carry payload_len > 0 across the skb->len
     * subtraction, so the variable-length load is bounded here: the barrier
     * stops clang from proving n != 0 and deleting the check, and the __u64
     * type keeps every compare and the helper argument on one 64-bit
     * register, where a range check folded onto a 32-bit copy would leave the
     * passed register unbounded. */
    __u64 n = payload_len;
    barrier_var(n);
    if (n == 0)
        return PROTO_UNKNOWN;
    if (n > sizeof(buf))
        n = sizeof(buf);
    if (bpf_skb_load_bytes(skb, payload_off, buf, n) < 0)
        return PROTO_UNKNOWN;

    if (n >= 4 && buf[0] == 'S' && buf[1] == 'S' && buf[2] == 'H' && buf[3] == '-')
        return PROTO_SSH;

    if (n == sizeof(buf)) {
        const char preface[24] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        int match = 1;
#pragma unroll
        for (int i = 0; i < 24; i++)
            if (buf[i] != (__u8)preface[i])
                match = 0;
        if (match)
            return PROTO_H2C;
    }

    if (n >= 5 && buf[0] == 0x16 && buf[1] == 0x03 && buf[2] >= 0x01 && buf[2] <= 0x04) {
        __u32 record_len = ((__u32)buf[3] << 8) | buf[4];
        /* a ClientHello split across segments takes the unknown rule, never tls */
        if (5 + record_len > payload_len)
            return PROTO_UNKNOWN;
        return parse_client_hello(skb, payload_off, 5 + record_len, alpn);
    }

    if (method_eq(buf, n, "GET", 3) || method_eq(buf, n, "PUT", 3) ||
        method_eq(buf, n, "POST", 4) || method_eq(buf, n, "HEAD", 4) ||
        method_eq(buf, n, "PATCH", 5) || method_eq(buf, n, "TRACE", 5) ||
        method_eq(buf, n, "DELETE", 6) || method_eq(buf, n, "OPTIONS", 7) ||
        method_eq(buf, n, "CONNECT", 7))
        return PROTO_HTTP11;

    return PROTO_UNKNOWN;
}

static __always_inline int handle_tcp(struct __sk_buff *skb, struct flow_key *fk, __u32 l4off)
{
    struct tcphdr_prefix tcp;
    if (bpf_skb_load_bytes(skb, l4off, &tcp, 13) < 0)
        return 1;
    fk->sport = tcp.source;
    fk->dport = tcp.dest;

    __u32 doff = ((__u32)(tcp.doff_res >> 4)) * 4;
    if (doff < 20)
        return 1;

    struct flow_state *st = bpf_map_lookup_elem(&flows, fk);
    if (st)
        return cached_verdict(st);

    /* skb->len starts at L3 for cgroup_skb */
    __u32 payload_off = l4off + doff;
    __u32 skb_len = skb->len;
    if (payload_off >= skb_len)
        return 1; /* no data yet: verdict deferred to the first data segment */

    char alpn[ALPN_MAX_LEN] = {};
    __u32 proto = classify_tcp(skb, payload_off, skb_len - payload_off, alpn);
    return settle(fk, proto, alpn);
}

static __always_inline int handle_udp(struct __sk_buff *skb, struct flow_key *fk, __u32 l4off)
{
    if (bpf_skb_load_bytes(skb, l4off, &fk->sport, 4) < 0)
        return 1;

    struct flow_state *st = bpf_map_lookup_elem(&flows, fk);
    if (st)
        return cached_verdict(st);

    __u32 proto = PROTO_UNKNOWN;
    __u32 payload_off = l4off + 8;
    __u32 skb_len = skb->len;
    if (payload_off < skb_len && skb_len - payload_off >= 5) {
        __u8 q[5];
        if (bpf_skb_load_bytes(skb, payload_off, q, 5) == 0 &&
            (q[0] & 0xF0) == 0xC0 &&
            q[1] == 0x00 && q[2] == 0x00 && q[3] == 0x00 && q[4] == 0x01)
            proto = PROTO_QUIC;
    }

    char alpn[ALPN_MAX_LEN] = {};
    return settle(fk, proto, alpn);
}

SEC("cgroup_skb/egress")
int proto_egress(struct __sk_buff *skb)
{
    struct flow_key fk = {};
    __u32 l4off;

    // cgroup_skb data starts at L3, so the IP family comes from skb->protocol;
    // parsing by the first payload byte would misread one family as the other.
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr iph;
        if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) < 0)
            return 1;
        __u32 ihl = ((__u32)(iph.ihl_version & 0x0F)) * 4;
        if (ihl < sizeof(iph))
            return 1;
        fk.family = 4;
        fk.l4proto = iph.protocol;
        __builtin_memcpy(fk.saddr, &iph.saddr, 4);
        __builtin_memcpy(fk.daddr, &iph.daddr, 4);
        l4off = ihl;

        /* a non-first fragment carries no L4 header, so its flow key cannot
         * be built; it passes, and the first fragment decides the flow */
        if (iph.frag_off & bpf_htons(0x1FFF))
            return 1;
    } else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr ip6;
        if (bpf_skb_load_bytes(skb, 0, &ip6, sizeof(ip6)) < 0)
            return 1;
        fk.family = 6;
        fk.l4proto = ip6.nexthdr;
        __builtin_memcpy(fk.saddr, ip6.saddr, 16);
        __builtin_memcpy(fk.daddr, ip6.daddr, 16);
        l4off = sizeof(ip6);
    } else {
        return 1;
    }

    if (fk.l4proto == IPPROTO_TCP)
        return handle_tcp(skb, &fk, l4off);
    if (fk.l4proto == IPPROTO_UDP)
        return handle_udp(skb, &fk, l4off);

    // No parseable L4 (ICMP, an IPv6 extension header chain): the flow must be
    // visible as unknown, not misparsed or dropped from observation.
    struct flow_state *st = bpf_map_lookup_elem(&flows, &fk);
    if (st)
        return cached_verdict(st);
    char alpn[ALPN_MAX_LEN] = {};
    return settle(&fk, PROTO_UNKNOWN, alpn);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
