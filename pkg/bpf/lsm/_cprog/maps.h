#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_PATH_LEN 128
#define EPERM 1

/* Kernel enforcement verdicts, recorded per observation so userspace can tell
 * an allowed open/exec from a denied one. Mirrored by
 * runtimeevent.KernelVerdict on the Go side; keep the values in sync. */
#define VERDICT_ALLOW 0
#define VERDICT_DENY 1

/* Key of the per-cgroup observation maps: one counter per (path, verdict).
 *
 * sizeof(struct path_event_key) is 132 with NO padding: MAX_PATH_LEN is 128, a
 * multiple of 4, so the __u32 verdict is already naturally aligned and the
 * struct needs no tail padding either. That matters because a hash map key is
 * compared as raw bytes -- uninitialized padding would make the same logical
 * (path, verdict) pair hash to distinct entries, producing phantom keys and
 * split counts. Callers must still zero-init the whole struct so the bytes of
 * `path` past the NUL terminator are defined. */
struct path_event_key {
    char path[MAX_PATH_LEN];
    __u32 verdict;
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

/* 2048, not 1024: the verdict dimension can double the number of distinct
 * keys, and a full map would silently drop exactly the deny observations the
 * verdict dimension exists to record. */
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