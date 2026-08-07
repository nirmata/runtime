#ifndef NIRMATA_RUNTIME_DNSQUERY_MAPS_H
#define NIRMATA_RUNTIME_DNSQUERY_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <dnsname.h>

/* The byte layout is the contract with decode.go; the assertions are the guard
 * rail. */
struct dns_query_event {
    __u64 cgroup_id;
    __u32 name_len;
    struct domain_key name;
};

_Static_assert(__builtin_offsetof(struct dns_query_event, name_len) == 8,
               "dns_query_event.name_len offset != 8");
_Static_assert(__builtin_offsetof(struct dns_query_event, name) == 12,
               "dns_query_event.name offset != 12");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgids SEC(".maps");

/* 64 KiB holds roughly 450 records. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

enum dns_query_stat {
    STAT_RINGBUF_FULL = 0,
    STAT_NAME_UNREADABLE = 1,
    STAT_MAX = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#endif /* NIRMATA_RUNTIME_DNSQUERY_MAPS_H */
