#ifndef KYVERNO_RUNTIME_EXECTRACE_MAPS_H
#define KYVERNO_RUNTIME_EXECTRACE_MAPS_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_ARGS 8
#define MAX_ARG_LEN 128
#define MAX_FILENAME_LEN 256

// exec_event is the ring buffer record. Its byte layout is the contract with
// pkg/bpf/exectrace/decode.go; the static assertions below are the guard rail.
//
// argv_len is the number of POPULATED argv slots, not a byte count. At 1312
// bytes this record cannot live on the BPF stack (512 byte limit), which is why
// the program reserves ring buffer space first and fills it in place.
struct exec_event {
    __u64 cgroup_id;
    __u32 pid; // thread group id, i.e. the pid userspace sees
    char comm[TASK_COMM_LEN];
    __u16 argv_len; // <= MAX_ARGS
    char filename[MAX_FILENAME_LEN];
    char argv[MAX_ARGS][MAX_ARG_LEN];
};

_Static_assert(__builtin_offsetof(struct exec_event, pid) == 8, "exec_event.pid offset != 8");
_Static_assert(__builtin_offsetof(struct exec_event, comm) == 12, "exec_event.comm offset != 12");
_Static_assert(__builtin_offsetof(struct exec_event, argv_len) == 28, "exec_event.argv_len offset != 28");
_Static_assert(__builtin_offsetof(struct exec_event, filename) == 30, "exec_event.filename offset != 30");
_Static_assert(__builtin_offsetof(struct exec_event, argv) == 286, "exec_event.argv offset != 286");

// The zeroing loop in exec.bpf.c stores whole __u64 words over the record.
_Static_assert(sizeof(struct exec_event) % 8 == 0, "exec_event size must be a multiple of 8");

// cgids gates event production in the kernel, exactly like lsm.bpf.c's map of
// the same name: userspace inserts only the cgroup ids of pods selected by a
// policy, so an unselected pod produces no ring buffer traffic at all. Without
// it this program would report every exec on the node.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgids SEC(".maps");

// events is the only output channel. Records are large (1312B), so the buffer is
// sized for bursts of ~200 execs.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Losses that produce no ring buffer record, or a record that under-reports.
// Neither is visible to a userspace reader of `events`, and both are missed
// detections rather than absence of activity.
enum exec_stat {
    STAT_ARGV_OVERFLOW = 0, // argc exceeded MAX_ARGS; argv reported truncated
    STAT_RINGBUF_FULL = 1,  // no record at all
    STAT_ARGV_UNREADABLE = 2, // argv pages not readable; argv reported short
    STAT_MAX = 3,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#endif // KYVERNO_RUNTIME_EXECTRACE_MAPS_H
