#ifndef KYVERNO_RUNTIME_NETFLOW_MAPS_H
#define KYVERNO_RUNTIME_NETFLOW_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define ADDR_LEN 16

// Re-emit a still-active flow at most once per window, so a long-lived
// connection stays visible without one record per packet.
#define FLOW_TTL_NS (30ULL * 1000000000ULL)

// flow_event is the ring buffer record. Its byte layout is the contract with
// pkg/bpf/netflow/decode.go; the static assertions below are the guard rail.
// Addresses are stored in wire order, IPv4 in the first 4 bytes with the rest
// zeroed.
struct flow_event {
    __u64 cgroup_id;
    __u32 pid;
    __u8 saddr[ADDR_LEN];
    __u8 daddr[ADDR_LEN];
    __u16 dport;  // host byte order: the program swaps the wire value
    __u8 proto;   // IANA protocol number (6 tcp, 17 udp)
    __u8 ip_ver;  // 4 or 6
    char comm[TASK_COMM_LEN];
};

_Static_assert(__builtin_offsetof(struct flow_event, pid) == 8, "flow_event.pid offset != 8");
_Static_assert(__builtin_offsetof(struct flow_event, saddr) == 12, "flow_event.saddr offset != 12");
_Static_assert(__builtin_offsetof(struct flow_event, daddr) == 28, "flow_event.daddr offset != 28");
_Static_assert(__builtin_offsetof(struct flow_event, dport) == 44, "flow_event.dport offset != 44");
_Static_assert(__builtin_offsetof(struct flow_event, proto) == 46, "flow_event.proto offset != 46");
_Static_assert(__builtin_offsetof(struct flow_event, ip_ver) == 47, "flow_event.ip_ver offset != 47");
_Static_assert(__builtin_offsetof(struct flow_event, comm) == 48, "flow_event.comm offset != 48");
_Static_assert(sizeof(struct flow_event) == 64, "flow_event sizeof != 64");

// flow_key identifies a destination for deduplication. Packed so the key has no
// uninitialized padding bytes (a hash map compares the whole key).
struct flow_key {
    __u64 cgroup_id;
    __u8 daddr[ADDR_LEN];
    __u16 dport;
    __u8 proto;
    __u8 ip_ver;
} __attribute__((packed));

// cgids gates event production in the kernel, exactly like lsm.bpf.c's map of
// the same name: userspace inserts only the cgroup ids of pods selected by a
// policy, so an unselected pod produces no ring buffer traffic at all.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgids SEC(".maps");

// seen_flows dedupes: value is the ktime the flow was last reported. LRU so a
// scanning workload evicts its own old entries instead of failing inserts.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, __u64);
} seen_flows SEC(".maps");

// events is the only output channel. A full buffer costs an observation, never
// a packet.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

#endif // KYVERNO_RUNTIME_NETFLOW_MAPS_H
