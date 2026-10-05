#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_PATH_LEN 128
#define MAX_PREFIX_DEPTH 16
#define EPERM 1

#define DECISION_ALLOW 0
#define DECISION_DENY 1

/* width of the policy-slot mask every entry carries as its value */
#define MAX_POLICIES 64

#define	PROG_TYPE_OPEN 0
#define	PROG_TYPE_EXEC 1

enum data_type {
    ALLOW_ENTRY,
    DENY_ENTRY,
    CGID,
    FLAGS,
    /* data holds a directory including its trailing '/', so that "/usr/lib/"
     * cannot match "/usr/library" */
    ALLOW_PREFIX_ENTRY,
    DENY_PREFIX_ENTRY,
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

/* one keyspace per dimension; the value is the set of policy slots that hold
 * the entry, one bit each, so a lookup answers for every policy at once */
struct policy_entries {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct entry);
    __type(value, __u64);
};

struct policy_entries open_entries SEC(".maps");
struct policy_entries exec_entries SEC(".maps");

/* Padding-free by construction: a hash key is compared as raw bytes, so any
 * uninitialized byte would split one logical key across separate entries. */
struct path_event_key {
    char path[MAX_PATH_LEN];
    __u32 decision;
    __u8 policy_suffix;
    __u8 padding[3];
};

struct policy_ctx {
    __u8 prog_type;
    __u8 reason;
    char path[MAX_PATH_LEN];
    char policy_path[MAX_PATH_LEN];
    /* nslash: count of path separators in that path
     * slash: the length of every path part after the separator
     */
    __u8 nslash;
    __u8 slash[MAX_PREFIX_DEPTH];
    __u8 policy_nslash;
    __u8 policy_slash[MAX_PREFIX_DEPTH];
    __u8 policy_suffix;
};

/* records the offset of every separator in ctx->path, up to MAX_PREFIX_DEPTH.
 * Unrolled so each path byte sits at a constant offset, and nslash is reloaded
 * through the map on every hit: a counter the verifier can see as a constant
 * costs a walk back over the whole loop history each time it is used as an
 * offset, which is what makes a rolled loop over 128 bytes exceed the budget */
static __always_inline void scan_separators(struct policy_ctx *ctx) {
    ctx->nslash = 0;
#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        char c = ctx->path[i];
        if (c == '\0') {
            break;
        }
        if (c != '/') {
            continue;
        }
        __u8 n = *(volatile __u8 *)&ctx->nslash;
        if (n >= MAX_PREFIX_DEPTH) {
            break;
        }
        ctx->slash[n] = i;
        ctx->nslash = n + 1;
    }
}

static __always_inline int is_procfs(struct file *file) {
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct super_block *sb = BPF_CORE_READ(dentry, d_sb);
    struct file_system_type *fs_type = BPF_CORE_READ(sb, s_type);
    const char *fs_name = BPF_CORE_READ(fs_type, name);
    char name[5] = {};
    bpf_probe_read_kernel_str(name, sizeof(name), fs_name);
    if (name[0] != 'p' || name[1] != 'r' || name[2] != 'o' || name[3] != 'c' || name[4] != '\0') {
        return 0;
    }
    return 1;
}

/* bpf_d_path resolves procfs links before the hook sees them and may return a
 * path relative to the proc mount. Retain that path for reporting and derive
 * the policy's explicit numeric-PID wildcard spelling for lookup. */
static __always_inline void set_proc_wildcard_policy_path(struct policy_ctx *ctx, struct file *file) {
    __builtin_memset(ctx->policy_path, 0, sizeof(ctx->policy_path));
    ctx->policy_suffix = 0;

    const char prefix[] = "/proc/";
    __u8 digit_start = 1;
    __u8 suffix = 0;
#pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(prefix) - 1; i++) {
        if (ctx->path[i] != prefix[i]) {
            digit_start = 1;
            break;
        }
        digit_start = sizeof(prefix) - 1;
    }
    if (digit_start == sizeof(prefix) - 1) {
        if (ctx->nslash < 3) {
            return;
        }
        suffix = ctx->slash[2];
    } else {
        if (ctx->path[0] != '/' || ctx->nslash < 2) {
            return;
        }
        suffix = ctx->slash[1];
    }
    if (suffix <= digit_start || suffix - digit_start > 20) {
        return;
    }

#pragma clang loop unroll(full)
    for (int i = 0; i < 20; i++) {
        if (digit_start + i >= suffix) {
            break;
        }
        char c = ctx->path[digit_start + i];
        if (c < '0' || c > '9') {
            return;
        }
    }
    if (!is_procfs(file)) {
        return;
    }

    const char wildcard[] = "/proc/*";
#pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(wildcard) - 1; i++) {
        ctx->policy_path[i] = wildcard[i];
    }
    bpf_probe_read_kernel_str(ctx->policy_path + sizeof(wildcard) - 1,
                              MAX_PATH_LEN - (sizeof(wildcard) - 1),
                              ctx->path + (suffix & (MAX_PATH_LEN - 1)));

    /* The canonical prefix contributes separators at 0 and 5, and the copied
     * suffix starts with the separator at 7. Translate later separators from
     * the already-scanned concrete path instead of scanning another 128 bytes;
     * this keeps the fmod_ret dispatcher inside older kernels' verifier budget. */
    ctx->policy_slash[0] = 0;
    ctx->policy_slash[1] = 5;
    ctx->policy_slash[2] = 7;
    ctx->policy_nslash = 3;
    ctx->policy_suffix = suffix;
#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_PREFIX_DEPTH; i++) {
        if (i >= ctx->nslash) {
            break;
        }
        __u8 slash = ctx->slash[i];
        if (slash <= suffix) {
            continue;
        }
        __u8 n = *(volatile __u8 *)&ctx->policy_nslash;
        if (n >= MAX_PREFIX_DEPTH) {
            break;
        }
        ctx->policy_slash[n] = slash - suffix + 7;
        ctx->policy_nslash = n + 1;
    }
}

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
