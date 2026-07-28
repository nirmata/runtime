// +build ignore

// tlspeek: cgroup_skb/egress TLS ClientHello peeker.
//
// It reuses the attach point already proven by pkg/bpf/egressfilter (cgroup
// egress, where skb->data starts at the network header, no L2), and on the
// FIRST data segment of a flow tries to read a TLS ClientHello out of the TCP
// payload. When it finds one it extracts the server_name (extension 0x0000)
// and the ALPN protocol list (extension 0x0010) and pushes a fixed-size
// tls_event to a ring buffer. The program never drops a packet: it always
// returns TLSPEEK_PASS.
//
// Deliberate limits (see also proposal §2.3 item 2):
//   - A ClientHello that is not entirely inside the first data segment is
//     ABANDONED. There is no kernel-side reassembly: a per-flow reassembly
//     buffer is exactly the kind of unbounded state a cgroup_skb program must
//     not hold, and the userspace consumer treats a missing SNI as "unknown"
//     rather than as an error.
//   - Every read is bounds-checked against data_end and every loop is bounded
//     by a compile-time constant, because the verifier accepts nothing else.
//   - The scan is capped at TLS_SCAN_LIMIT bytes from the start of the TCP
//     payload; a ClientHello with more preceding material than that is
//     abandoned too.
//   - pid/comm come from the CURRENT task, which is the sending task only
//     while the packet is produced in process context (the common
//     sendmsg/write path). For segments produced by a softirq retransmit or
//     by TSQ they are meaningless; userspace must treat cgroup_id as the
//     authoritative attribution key and pid/comm as hints.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TLSPEEK_PASS 1

#define MAX_SNI_LEN 256
#define MAX_ALPN_LEN 32
#define MAX_COMM_LEN 16

// TLS_SCAN_LIMIT bounds every variable offset used against the packet pointer
// so the verifier can keep a range on it.
#define TLS_SCAN_LIMIT 1024
// MAX_EXTENSIONS bounds the extension walk. 16 covers every real client;
// a hello with more extensions before server_name is abandoned.
#define MAX_EXTENSIONS 16

#define TLS_RECORD_HANDSHAKE 0x16
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01
#define TLS_EXT_SERVER_NAME 0x0000
#define TLS_EXT_ALPN 0x0010
#define TLS_SNI_TYPE_HOST_NAME 0x00

#define IPPROTO_TCP_ 6

// Local header definitions: this program needs no CO-RE and therefore no
// vmlinux.h. Unlike egressfilter/_cprog/probe.c it does NOT assume a 20 byte
// IPv4 header -- ihl is honored.
struct tp_iphdr {
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

struct tp_ipv6hdr {
    __u8 priority_version;
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
};

struct tp_tcphdr {
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

// tls_event MUST stay byte-for-byte identical to tlspeek.DecodeTLSEvent's
// layout in decode.go. Field order is chosen so there is no interior padding:
// 8 + 4 + 2 + 2 + 2 + 256 + 32 + 16 = 322 bytes of fields, and the only
// padding is the 6 trailing bytes the compiler adds for the 8 byte alignment
// of cgroup_id (the decoder tolerates trailing bytes).
struct tls_event {
    __u64 cgroup_id;
    __u32 pid;
    __u16 dport;
    __u16 sni_len;
    __u16 alpn_len;
    __u8 sni[MAX_SNI_LEN];
    // alpn holds the RAW ProtocolNameList body: a sequence of
    // {__u8 len; len bytes} entries, WITHOUT the outer 2 byte list length.
    // Userspace walks it; the kernel does not interpret it.
    __u8 alpn[MAX_ALPN_LEN];
    __u8 comm[MAX_COMM_LEN];
};

// cgids selects which cgroups produce events, exactly as in
// pkg/bpf/lsm/_cprog/lsm.bpf.c. Without it a node-wide ring buffer of every
// egress flow would melt.
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

// seen_flows makes the peek once-per-flow. LRU so it cannot fill up: evicting
// an entry costs at most a duplicate event, never a leak.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, __u8);
} seen_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// read_u8/read_u16 are the only way this program touches the packet: both
// bounds-check against data_end before dereferencing.
static __always_inline int read_u8(void *base, __u32 off, void *data_end, __u8 *out)
{
    if (off > TLS_SCAN_LIMIT)
        return -1;
    void *p = base + off;
    if (p + 1 > data_end)
        return -1;
    *out = *(volatile __u8 *)p;
    return 0;
}

static __always_inline int read_u16(void *base, __u32 off, void *data_end, __u16 *out)
{
    __u8 hi = 0, lo = 0;
    if (read_u8(base, off, data_end, &hi) < 0)
        return -1;
    if (read_u8(base, off + 1, data_end, &lo) < 0)
        return -1;
    *out = ((__u16)hi << 8) | (__u16)lo; /* TLS is big-endian on the wire */
    return 0;
}

// copy_sni copies name_len bytes from base+off into ev->sni. Bounded by
// MAX_SNI_LEN and bounds-checked per byte.
static __always_inline __u16 copy_sni(struct tls_event *ev, void *base, __u32 off,
                                      __u16 name_len, void *data_end)
{
    __u16 n = 0;
#pragma unroll
    for (int i = 0; i < MAX_SNI_LEN; i++) {
        if (i >= name_len)
            break;
        __u8 c = 0;
        if (read_u8(base, off + i, data_end, &c) < 0)
            return 0; /* truncated: report no SNI rather than a partial host */
        ev->sni[i] = c;
        n++;
    }
    return n;
}

static __always_inline __u16 copy_alpn(struct tls_event *ev, void *base, __u32 off,
                                       __u16 list_len, void *data_end)
{
    __u16 n = 0;
#pragma unroll
    for (int i = 0; i < MAX_ALPN_LEN; i++) {
        if (i >= list_len)
            break;
        __u8 c = 0;
        if (read_u8(base, off + i, data_end, &c) < 0)
            return 0;
        ev->alpn[i] = c;
        n++;
    }
    return n;
}

// l4_offset returns the offset of the TCP header and fills daddr/ipver, or -1.
static __always_inline int l4_offset(void *data, void *data_end, __u8 daddr[16], __u8 *ipver)
{
    __u8 ver = 0;
    if (data + 1 > data_end)
        return -1;
    ver = (*(volatile __u8 *)data) >> 4;

    if (ver == 4) {
        struct tp_iphdr *ip = data;
        if ((void *)(ip + 1) > data_end)
            return -1;
        if (ip->protocol != IPPROTO_TCP_)
            return -1;
        __u32 ihl = (ip->ihl_version & 0x0f) * 4;
        if (ihl < sizeof(struct tp_iphdr))
            return -1;
        /* IPv4 mapped into the 16 byte field, ::ffff:a.b.c.d style. */
        daddr[10] = 0xff;
        daddr[11] = 0xff;
        __builtin_memcpy(&daddr[12], &ip->daddr, 4);
        *ipver = 4;
        return (int)ihl;
    }
    if (ver == 6) {
        struct tp_ipv6hdr *ip6 = data;
        if ((void *)(ip6 + 1) > data_end)
            return -1;
        /* No extension header walking: an IPv6 flow whose first header is not
         * TCP is abandoned rather than guessed at. */
        if (ip6->nexthdr != IPPROTO_TCP_)
            return -1;
        __builtin_memcpy(daddr, ip6->daddr, 16);
        *ipver = 6;
        return (int)sizeof(struct tp_ipv6hdr);
    }
    return -1;
}

SEC("cgroup_skb/egress")
int tls_peek(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u64 cgid = bpf_skb_cgroup_id(skb);
    if (cgid == 0)
        cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&cgids, &cgid))
        return TLSPEEK_PASS;

    __u8 daddr[16] = {};
    __u8 ipver = 0;
    int ip_len = l4_offset(data, data_end, daddr, &ipver);
    if (ip_len < 0)
        return TLSPEEK_PASS;

    struct tp_tcphdr *tcp = data + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return TLSPEEK_PASS;
    __u32 doff = (tcp->doff_res >> 4) * 4;
    if (doff < sizeof(struct tp_tcphdr))
        return TLSPEEK_PASS;
    __u16 dport = bpf_ntohs(tcp->dest);

    void *payload = (void *)tcp + doff;
    if (payload + 6 > data_end)
        return TLSPEEK_PASS; /* no room for a record header + handshake type */

    /* Record header: type, version major/minor, 2 byte length. */
    __u8 rec_type = 0, ver_major = 0, hs_type = 0;
    if (read_u8(payload, 0, data_end, &rec_type) < 0)
        return TLSPEEK_PASS;
    if (rec_type != TLS_RECORD_HANDSHAKE)
        return TLSPEEK_PASS;
    if (read_u8(payload, 1, data_end, &ver_major) < 0)
        return TLSPEEK_PASS;
    if (ver_major != 0x03)
        return TLSPEEK_PASS;
    if (read_u8(payload, 5, data_end, &hs_type) < 0)
        return TLSPEEK_PASS;
    if (hs_type != TLS_HANDSHAKE_CLIENT_HELLO)
        return TLSPEEK_PASS;

    /* Once per flow. Done after the ClientHello check so a flow whose first
     * segment is not a hello can still be peeked on a later segment. */
    struct flow_key fk = {};
    fk.cgid = cgid;
    fk.dport = dport;
    __builtin_memcpy(fk.daddr, daddr, 16);
    if (bpf_map_lookup_elem(&seen_flows, &fk))
        return TLSPEEK_PASS;

    /* offsets are relative to payload:
     *  0  record type
     *  5  handshake type
     *  6  handshake length (3)
     *  9  client_version (2)
     * 11  random (32)
     * 43  session_id_len (1) */
    __u32 off = 43;
    __u8 sid_len = 0;
    if (read_u8(payload, off, data_end, &sid_len) < 0)
        return TLSPEEK_PASS;
    off += 1 + sid_len;

    __u16 cs_len = 0;
    if (read_u16(payload, off, data_end, &cs_len) < 0)
        return TLSPEEK_PASS;
    off += 2 + cs_len;

    __u8 comp_len = 0;
    if (read_u8(payload, off, data_end, &comp_len) < 0)
        return TLSPEEK_PASS;
    off += 1 + comp_len;

    __u16 ext_total = 0;
    if (read_u16(payload, off, data_end, &ext_total) < 0)
        return TLSPEEK_PASS; /* no extensions at all -> nothing to report */
    off += 2;

    __u32 sni_off = 0, alpn_off = 0;
    __u16 sni_len = 0, alpn_len = 0;

#pragma unroll
    for (int i = 0; i < MAX_EXTENSIONS; i++) {
        __u16 ext_type = 0, ext_len = 0;
        if (read_u16(payload, off, data_end, &ext_type) < 0)
            break;
        if (read_u16(payload, off + 2, data_end, &ext_len) < 0)
            break;
        __u32 body = off + 4;

        if (ext_type == TLS_EXT_SERVER_NAME) {
            /* server_name_list: 2 byte list length, then entries of
             * {type(1), length(2), name}. Only the first host_name entry is
             * taken -- clients send exactly one. */
            __u8 name_type = 0;
            __u16 name_len = 0;
            if (read_u8(payload, body + 2, data_end, &name_type) == 0 &&
                name_type == TLS_SNI_TYPE_HOST_NAME &&
                read_u16(payload, body + 3, data_end, &name_len) == 0) {
                if (name_len > MAX_SNI_LEN)
                    name_len = MAX_SNI_LEN; /* oversize: keep the prefix */
                sni_off = body + 5;
                sni_len = name_len;
            }
        } else if (ext_type == TLS_EXT_ALPN) {
            __u16 list_len = 0;
            if (read_u16(payload, body, data_end, &list_len) == 0) {
                if (list_len > MAX_ALPN_LEN)
                    list_len = MAX_ALPN_LEN;
                alpn_off = body + 2;
                alpn_len = list_len;
            }
        }

        off = body + ext_len;
        if (off > TLS_SCAN_LIMIT)
            break;
    }

    if (sni_len == 0 && alpn_len == 0)
        return TLSPEEK_PASS; /* nothing worth an event */

    struct tls_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        /* Ring buffer full: record the flow anyway so a hot flow cannot spin
         * on reserve failures forever. Userspace counts drops via the map. */
        __u8 one = 1;
        bpf_map_update_elem(&seen_flows, &fk, &one, BPF_ANY);
        return TLSPEEK_PASS;
    }
    /* Reserved ring buffer memory is NOT zeroed -- clear it before filling in
     * so no stale kernel bytes reach userspace. */
    __builtin_memset(ev, 0, sizeof(*ev));

    ev->cgroup_id = cgid;
    ev->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    ev->dport = dport;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    if (sni_len > 0)
        ev->sni_len = copy_sni(ev, payload, sni_off, sni_len, data_end);
    if (alpn_len > 0)
        ev->alpn_len = copy_alpn(ev, payload, alpn_off, alpn_len, data_end);

    if (ev->sni_len == 0 && ev->alpn_len == 0) {
        bpf_ringbuf_discard(ev, 0);
        return TLSPEEK_PASS;
    }

    bpf_ringbuf_submit(ev, 0);

    __u8 one = 1;
    bpf_map_update_elem(&seen_flows, &fk, &one, BPF_ANY);
    return TLSPEEK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
