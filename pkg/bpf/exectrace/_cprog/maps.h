#ifndef KYVERNO_RUNTIME_EXECTRACE_MAPS_H
#define KYVERNO_RUNTIME_EXECTRACE_MAPS_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_ARGS 8
#define MAX_ARG_LEN 128
#define MAX_FILENAME_LEN 256

// byte-for-byte contract with pkg/bpf/exectrace/decode.go, pinned by the
// static assertions below
struct exec_event {
    __u64 cgroup_id;
    __u32 pid; // thread group id, i.e. the pid userspace sees
    char comm[TASK_COMM_LEN];
    __u16 argv_len; // populated argv slots, not bytes; <= MAX_ARGS
    char filename[MAX_FILENAME_LEN];
    char argv[MAX_ARGS][MAX_ARG_LEN];
};

_Static_assert(__builtin_offsetof(struct exec_event, pid) == 8, "exec_event.pid offset != 8");
_Static_assert(__builtin_offsetof(struct exec_event, comm) == 12, "exec_event.comm offset != 12");
_Static_assert(__builtin_offsetof(struct exec_event, argv_len) == 28, "exec_event.argv_len offset != 28");
_Static_assert(__builtin_offsetof(struct exec_event, filename) == 30, "exec_event.filename offset != 30");
_Static_assert(__builtin_offsetof(struct exec_event, argv) == 286, "exec_event.argv offset != 286");

// zero_event stores whole __u64 words over the record
_Static_assert(sizeof(struct exec_event) % 8 == 0, "exec_event size must be a multiple of 8");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgids SEC(".maps");

// sized for bursts of ~200 records of sizeof(struct exec_event)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

enum exec_stat {
    STAT_ARGV_OVERFLOW = 0,
    STAT_RINGBUF_FULL = 1,
    STAT_ARGV_UNREADABLE = 2,
    STAT_MAX = 3,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#endif // KYVERNO_RUNTIME_EXECTRACE_MAPS_H
