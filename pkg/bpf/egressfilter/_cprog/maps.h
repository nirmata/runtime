
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_DENY 1
#define LEARNING_MODE 2

/* Kernel enforcement verdicts, recorded per observation so userspace can tell
 * an allowed flow from a denied one. Mirrored by runtimeevent.KernelVerdict on
 * the Go side; keep the values in sync. */
#define VERDICT_ALLOW 0
#define VERDICT_DENY 1

/* Key of the ip_events observation map: one counter per (destination, verdict).
 *
 * Both members are deliberately __u32: two naturally-aligned 32-bit words give
 * sizeof(struct ip_event_key) == 8 with NO padding bytes. That matters because
 * a hash map key is compared as raw bytes -- uninitialized padding would make
 * the same logical (daddr, verdict) pair hash to distinct entries, producing
 * phantom keys and split counts. */
struct ip_event_key {
    __u32 daddr;
    __u32 verdict;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} banned_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} allowed_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} flags SEC(".maps");

/* 2048, not 1024: the verdict dimension can double the number of distinct
 * keys, and a full map would silently drop exactly the deny observations the
 * verdict dimension exists to record. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct ip_event_key);
    __type(value, __u32);
} ip_events SEC(".maps");
