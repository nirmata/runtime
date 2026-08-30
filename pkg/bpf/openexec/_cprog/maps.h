#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_PATH_LEN 128
#define EPERM 1

#define DECISION_ALLOW 0
#define DECISION_DENY 1


#define MAX_PROG_COUNT 128

#define	PROG_TYPE_OPEN 0
#define	PROG_TYPE_EXEC 1

enum data_type {
    ALLOW_ENTRY,
    DENY_ENTRY,
    CGID,
    FLAGS,
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

struct entry{
    enum data_type data_type;
    char data[MAX_PATH_LEN]; 
};

struct policy_entry_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct entry);
    __type(value, __u8);
};

struct policy_entry_map inner_policy_map SEC(".maps");

/* the structs holding the actual policy information (allow, deny, cgids.. etc) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 128); // 128 policies max
    __type(key, __u32);
    __array(values, struct policy_entry_map);
} open_policies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 128); // 128 policies max
    __type(key, __u32);
    __array(values, struct policy_entry_map);
} exec_policies SEC(".maps");

/* Padding-free by construction: a hash key is compared as raw bytes, so any
 * uninitialized byte would split one logical key across separate entries. */
struct path_event_key {
    char path[MAX_PATH_LEN];
    __u32 decision;
};

struct policy_ctx {
    __u8 prog_type;
    __u8 reason;
    char path[MAX_PATH_LEN];
};

/* 2048: the decision dimension can double the number of distinct keys. */
struct events_inner_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct path_event_key);
    __type(value, __u32);
};

struct events_inner_map inner_events SEC(".maps"); // (ammar) why the need to declare a variable with the template though ?

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u32);
    __array(values, struct events_inner_map);
} events_map SEC(".maps");

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


/* the single policy enforcer for every type from exec and open */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} open_prog SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} exec_prog SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_ctx);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ctx_map SEC(".maps");
