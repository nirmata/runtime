#ifndef NIRMATA_RUNTIME_DNSQUERY_MAPS_H
#define NIRMATA_RUNTIME_DNSQUERY_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <dnsname.h>

/* dns_query_event is the ring buffer record, and its byte layout is the contract
 * with decode.go; the static assertions below are the guard rail.
 *
 * name holds the same bytes userspace interns for a policy-named domain, so a
 * comparison needs no re-encoding on either side.
 *
 * There is no process name and no pid: bpf_get_current_comm is not among the
 * helpers a cgroup_skb program may call, and the cgroup id is what attribution
 * resolves a pod from. */
struct dns_query_event {
    __u64 cgroup_id;
    __u32 name_len;
    struct domain_key name;
};

_Static_assert(__builtin_offsetof(struct dns_query_event, name_len) == 8,
               "dns_query_event.name_len offset != 8");
_Static_assert(__builtin_offsetof(struct dns_query_event, name) == 12,
               "dns_query_event.name offset != 12");

/* Userspace admits only the cgroup ids of pods a dns behavior selects, so an
 * unselected pod produces no ring buffer traffic at all. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgids SEC(".maps");

/* 64 KiB holds roughly 450 records. Questions are rare next to packets, and a
 * full buffer costs an observation rather than a packet. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} events SEC(".maps");

/* Every path that reaches a selected pod's question and then fails to deliver it
 * bumps one of these. A lost observation is indistinguishable from an absent one
 * at the sink, so userspace exports the deltas. */
enum dns_query_stat {
    STAT_RINGBUF_FULL = 0,  /* reserve failed: the reader is behind */
    STAT_NAME_UNREADABLE = 1, /* truncated, compressed, or over the key width */
    STAT_MAX = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(enum dns_query_stat which)
{
    __u32 key = (__u32)which;
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v)
        *v += 1;
}

#endif /* NIRMATA_RUNTIME_DNSQUERY_MAPS_H */
