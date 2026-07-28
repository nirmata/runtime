#ifndef KYVERNO_RUNTIME_EXECTRACE_MAPS_H
#define KYVERNO_RUNTIME_EXECTRACE_MAPS_H

#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_ARGS 8
#define MAX_ARG_LEN 128
#define MAX_FILENAME_LEN 256

// exec_event is the ring buffer record. Its byte layout is the contract with
// pkg/bpf/exectrace/decode.go; the static assertions below are the guard rail.
//
// argv_len is the number of POPULATED argv slots, not a byte count. At 1320
// bytes this record cannot live on the BPF stack (512 byte limit), which is why
// the program reserves ring buffer space first and fills it in place.
struct exec_event {
    __u64 cgroup_id;
    __u32 pid; // thread group id, i.e. the pid userspace sees
    __u32 ppid;
    char comm[TASK_COMM_LEN];
    __u16 argv_len; // <= MAX_ARGS
    char filename[MAX_FILENAME_LEN];
    char argv[MAX_ARGS][MAX_ARG_LEN];
};

_Static_assert(__builtin_offsetof(struct exec_event, pid) == 8, "exec_event.pid offset != 8");
_Static_assert(__builtin_offsetof(struct exec_event, ppid) == 12, "exec_event.ppid offset != 12");
_Static_assert(__builtin_offsetof(struct exec_event, comm) == 16, "exec_event.comm offset != 16");
_Static_assert(__builtin_offsetof(struct exec_event, argv_len) == 32, "exec_event.argv_len offset != 32");
_Static_assert(__builtin_offsetof(struct exec_event, filename) == 34, "exec_event.filename offset != 34");
_Static_assert(__builtin_offsetof(struct exec_event, argv) == 290, "exec_event.argv offset != 290");

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

// events is the only output channel. Records are large (1320B), so the buffer is
// sized for bursts of ~200 execs.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

#endif // KYVERNO_RUNTIME_EXECTRACE_MAPS_H
