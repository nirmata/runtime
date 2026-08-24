#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_PATH_LEN 128
#define EPERM 1

#define DECISION_ALLOW 0
#define DECISION_DENY 1


// programs are limited by tail call count. in the future we can check if we
// can optimizing this by only tail calling to programs if they target a particular
// cgid (pod) rather than every program we have
#define MAX_PROG_COUNT 33

/* these are prog_count keys; the order matches lsm.ProgTypes in the Go layer */
#define	PROG_TYPE_LSM_OPEN 0
#define	PROG_TYPE_LSM_EXEC 1


/* Padding-free by construction: a hash key is compared as raw bytes, so any
 * uninitialized byte would split one logical key across separate entries. */
struct path_event_key {
    char path[MAX_PATH_LEN];
    __u32 decision;
};

enum path_stat {
    PATH_STAT_COUNT_MAP_FULL = 0,
    PATH_STAT_MAX = 1,
};

enum decision_reason {
    EXPLICIT_DENY,
    IMPLICIT_DENY,
    EXPLICIT_ALLOW,
    IMPLICIT_ALLOW,
};

struct lsm_ctx {
    __u8 deny;
    __u8 next_prog_idx;
    __u8 have_executed;
    __u8 prog_type;
    __u8 reason;
    char path[MAX_PATH_LEN];
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

/* 2048: the decision dimension can double the number of distinct keys. */
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
} open_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PATH_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2); // one for exec and one for open
    __type(key, __u32);
    __type(value, __u8); // since we can have 128 max anyways
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} prog_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_PROG_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} open_progs SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_PROG_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} exec_progs SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lsm_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ctx_map SEC(".maps");
