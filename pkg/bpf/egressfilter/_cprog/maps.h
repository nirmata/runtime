
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_DENY 1
#define LEARNING_MODE 2

#define DECISION_ALLOW 0
#define DECISION_DENY 1

#include <dnsname.h>

/* Padding-free by construction: a hash key is compared as raw bytes.
 * domain_id is 0 when the address was never seen in a snooped DNS answer. */
struct ip_event_key {
    __u32 daddr;
    __u32 decision;
    __u32 domain_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} banned_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} allowed_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} flags SEC(".maps");

/* 2048: the decision dimension can double the number of distinct keys. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct ip_event_key);
    __type(value, __u32);
} ip_events SEC(".maps");

/* A name absent here was never named by a policy; the snooper ignores its
 * answers entirely. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct domain_key);
    __type(value, __u32);
} domain_ids SEC(".maps");

/* Written by the snooper, read by the egress program. LRU so a rotating answer
 * set evicts stale addresses instead of failing inserts. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} ip_domain SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} allowed_domains SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} banned_domains SEC(".maps");
