#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_PATH_LEN 128
#define EPERM 1

// lets say that having a 1 set in the u8 means that this cgid should have learning mode enabled
// which would mean that learning mode on this program shouldn't be just a flag
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u8);
    __type(value, __u8);
} argtypes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u8);
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_PATH_LEN]);
    __type(value, __u32);
} open_events SEC(".maps");