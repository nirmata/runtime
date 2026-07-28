#ifndef KYVERNO_RUNTIME_DNSTRACE_MAPS_H
#define KYVERNO_RUNTIME_DNSTRACE_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_QNAME 253
#define TASK_COMM_LEN 16

// dns_event is the ring buffer record. Its byte layout is the contract with
// pkg/bpf/dnstrace/decode.go; the static assertions below are the guard rail.
//
// qname holds the RAW wire-format label sequence (length-prefixed labels,
// WITHOUT the terminating root byte) and qname_len the number of bytes copied.
// Converting that to a dotted name is userspace's job: it keeps the kernel loop
// a bounded byte copy and moves all the parsing into unit-tested Go.
struct dns_event {
    __u64 cgroup_id;
    __u32 pid;
    __u16 qtype;     // host byte order: the program swaps the wire value
    __u16 qname_len; // <= MAX_QNAME
    char comm[TASK_COMM_LEN];
    __u8 qname[MAX_QNAME];
};

_Static_assert(__builtin_offsetof(struct dns_event, pid) == 8, "dns_event.pid offset != 8");
_Static_assert(__builtin_offsetof(struct dns_event, qtype) == 12, "dns_event.qtype offset != 12");
_Static_assert(__builtin_offsetof(struct dns_event, qname_len) == 14, "dns_event.qname_len offset != 14");
_Static_assert(__builtin_offsetof(struct dns_event, comm) == 16, "dns_event.comm offset != 16");
_Static_assert(__builtin_offsetof(struct dns_event, qname) == 32, "dns_event.qname offset != 32");

// cgids gates event production in the kernel, exactly like lsm.bpf.c's map of
// the same name: userspace inserts only the cgroup ids of pods selected by a
// policy, so an unselected pod produces no ring buffer traffic at all.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgids SEC(".maps");

// events is the only output channel. 256 KiB: DNS queries are rare compared to
// packets, and a full buffer costs an observation, never a packet.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

#endif // KYVERNO_RUNTIME_DNSTRACE_MAPS_H
