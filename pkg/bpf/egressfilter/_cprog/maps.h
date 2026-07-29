
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_DENY 1
#define LEARNING_MODE 2

#define DECISION_ALLOW 0
#define DECISION_DENY 1

/* Padding-free by construction: a hash key is compared as raw bytes, so any
 * uninitialized byte would split one logical key across separate entries. */
struct ip_event_key {
    __u32 daddr;
    __u32 decision;
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
