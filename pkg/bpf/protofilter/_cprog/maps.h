
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_DENY 1
#define LEARNING_MODE 2

#define DECISION_ALLOW 0
#define DECISION_DENY 1

#define PROTO_UNKNOWN 0
#define PROTO_SSH 1
#define PROTO_TLS 2
#define PROTO_HTTP11 3
#define PROTO_H2C 4
#define PROTO_QUIC 5

#define ALPN_MAX_LEN 16

/* Padding-free by construction: a hash key is compared as raw bytes, so any
 * uninitialized byte would split one logical key across separate entries. */
struct proto_key {
    __u32 proto;
    char alpn[ALPN_MAX_LEN];
};

struct proto_event_key {
    __u32 proto;
    char alpn[ALPN_MAX_LEN];
    __u32 decision;
};

/* 38 bytes at 2-byte alignment, padding-free. IPv4 addresses occupy the first
 * 4 bytes of the zeroed 16-byte arrays. */
struct flow_key {
    __u8 saddr[16];
    __u8 daddr[16];
    __be16 sport;
    __be16 dport;
    __u8 l4proto;
    __u8 family;
};

struct flow_state {
    __u32 proto;
    char alpn[ALPN_MAX_LEN];
    __u32 decision;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct proto_key);
    __type(value, __u8);
} allowed_protos SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct proto_key);
    __type(value, __u8);
} banned_protos SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} flags SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct proto_event_key);
    __type(value, __u32);
} proto_events SEC(".maps");
