#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_PATH_LEN 128
#define EPERM 1

#define DECISION_ALLOW 0
#define DECISION_DENY 1

/* Padding-free by construction: a hash key is compared as raw bytes, so any
 * uninitialized byte would split one logical key across separate entries. */
struct path_event_key {
    char path[MAX_PATH_LEN];
    __u32 decision;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} default_deny SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_PATH_LEN]);
    __type(value, __u8);
} banned SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_PATH_LEN]);
    __type(value, __u8);
} allowed SEC(".maps");

/* 2048: the decision dimension can double the number of distinct keys. */
struct open_events_inner_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct path_event_key);
    __type(value, __u32);
};

struct open_events_inner_map inner_open_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u32);
    __array(values, struct open_events_inner_map);
} open_events SEC(".maps") = {
    .values = { &inner_open_events },
};