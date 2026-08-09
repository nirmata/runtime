// +build ignore

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

// TODO: how do avoid defining those twice
#define DEFAULT_DENY 1
#define LEARNING_MODE 2

#if !defined(LSM_FILE_OPEN) && !defined(LSM_EXEC_CHECK)
#error "must build lsm.bpf.c with exactly one of -DLSM_FILE_OPEN or -DLSM_EXEC_CHECK defined"
#endif

#if defined(LSM_FILE_OPEN) && defined(LSM_EXEC_CHECK)
#error "must build lsm.bpf.c with exactly one of -DLSM_FILE_OPEN or -DLSM_EXEC_CHECK defined"
#endif

// The policy maps are keyed by char[MAX_PATH_LEN], hence key->path rather than
// the whole event key.
static __always_inline __u32 path_decision(struct path_event_key *key) {
    __u32 dd_key = 0;
    __u8 *dd = bpf_map_lookup_elem(&default_deny, &dd_key);

    if (dd) {
        if (bpf_map_lookup_elem(&allowed, key->path) == NULL) {
            return DECISION_DENY;
        }
        return DECISION_ALLOW;
    }

    if (bpf_map_lookup_elem(&banned, key->path) != NULL) {
        return DECISION_DENY;
    }
    return DECISION_ALLOW;
}

static __always_inline void record_path_event(__u64 *cgid, struct path_event_key *key) {
    struct bpf_map *count_map = bpf_map_lookup_elem(&open_events, cgid);
    if (!count_map) {
        return;
    }

    __u32 *count = bpf_map_lookup_elem(count_map, key);
    if (count) {
        __sync_fetch_and_add(count, 1);
        return;
    }

    __u32 init_count = 1;
    if (bpf_map_update_elem(count_map, key, &init_count, BPF_NOEXIST) != 0) {
        // lost the create race with another CPU: the entry exists now, add to it
        count = bpf_map_lookup_elem(count_map, key);
        if (count) {
            __sync_fetch_and_add(count, 1);
            return;
        }
        __u32 stat = PATH_STAT_COUNT_MAP_FULL;
        __u64 *v = bpf_map_lookup_elem(&stats, &stat);
        if (v) {
            *v += 1; // per-CPU value, so no atomic
        }
    }
}

// Both handlers are ordered decision -> record -> return, so no enforcement
// return can skip the observation call.

#if defined(LSM_FILE_OPEN)
static __always_inline int handle_open(__u64 *args, __u64 *cgid) {
    __u64 arg0 = args[0];
    struct file *f = (struct file *)arg0;
    char buf[MAX_PATH_LEN] = {};
    bpf_d_path(&f->f_path, buf, sizeof(buf));

    struct path_event_key key = {};
    bpf_probe_read_kernel_str(key.path, sizeof(key.path), buf);

    key.decision = path_decision(&key);

    record_path_event(cgid, &key);

    if (key.decision == DECISION_DENY) {
        return -EPERM;
    }
    return 0;
}
#endif // LSM_FILE_OPEN

#if defined(LSM_EXEC_CHECK)
static __always_inline int handle_exec(__u64 *args, __u64 *cgid) {
    __u64 arg0 = args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)arg0;
    char buf[MAX_PATH_LEN] = {};
    bpf_d_path(&bprm->file->f_path, buf, sizeof(buf));

    struct path_event_key key = {};
    bpf_probe_read_kernel_str(key.path, sizeof(key.path), buf);

    key.decision = path_decision(&key);

    record_path_event(cgid, &key);

    if (key.decision == DECISION_DENY) {
        return -EPERM;
    }
    return 0;
}
#endif // LSM_EXEC_CHECK

SEC("lsm/generic_handler")
int generic_lsm_handler(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    __u64 *args = (__u64*)ctx;

    __u8 *val = bpf_map_lookup_elem(&cgids, &cgid);
    if (!val) {
        return 0;
    }

#if defined(LSM_FILE_OPEN)
    return handle_open(args, &cgid);
#elif defined(LSM_EXEC_CHECK)
    return handle_exec(args, &cgid);
#endif
}

char LICENSE[] SEC("license") = "GPL";
