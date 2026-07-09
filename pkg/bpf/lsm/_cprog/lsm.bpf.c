// +build ignore

#include "include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

// TODO: how do avoid defining those twice
#define DEFAULT_DENY 1
#define LEARNING_MODE 2

// argtype values written into the `argtypes` map from userspace (see lsm.go's
// argTypeFileOpen / argTypeExecCheck). must stay in sync with those.
#define ARGTYPE_FILE_OPEN 1
#define ARGTYPE_EXEC_CHECK 2


static __always_inline int handle_open(__u64 *args, __u64 *cgid) {
    __u64 arg0 = args[0];
    struct file *f = (struct file *)arg0;
    char buf[MAX_PATH_LEN] = {};
    bpf_d_path(&f->f_path, buf, sizeof(buf));

    char key[MAX_PATH_LEN] = {};
    bpf_probe_read_kernel_str(key, sizeof(key), buf); 


    struct bpf_map *count_map = bpf_map_lookup_elem(&open_events, cgid);
    if (count_map) {
        __u32 *open_count = bpf_map_lookup_elem(count_map, &key);
        if (open_count) {
            (*open_count)++;
        } else {
            __u32 init_count = 1;
            bpf_map_update_elem(count_map, &key, &init_count, BPF_ANY);
        };
    }

    __u32 dd_key = 0;
    __u8 *dd = bpf_map_lookup_elem(&default_deny, &dd_key);

    // there's a default deny. consult the allow list
    if (dd) {
        __u8 *val = bpf_map_lookup_elem(&allowed, &key);
        if (val) {
            return 0;
        }
        return -EPERM;
    }

    __u8 *val = bpf_map_lookup_elem(&banned, &key);
    if (val) {
        return -EPERM;
    }
    return 0;
}

static __always_inline int handle_exec(__u64 *args, __u64 *cgid) {
    __u64 arg0 = args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)arg0;
    char key[MAX_PATH_LEN] = {};
    const char *fname = BPF_CORE_READ(bprm, filename);
    int len = bpf_probe_read_kernel_str(key, sizeof(key), fname);
    if (len <= 0) {
        return 0;
    }

    struct bpf_map *count_map = bpf_map_lookup_elem(&open_events, cgid);
    if (count_map) {
        __u32 *open_count = bpf_map_lookup_elem(count_map, &key);
        if (open_count) {
            (*open_count)++;
        } else {
            __u32 init_count = 1;
            bpf_map_update_elem(count_map, &key, &init_count, BPF_ANY);
        };
    }

    // should be if there was a value in the open events map
    __u32 dd_key = 0;
    __u8 *dd = bpf_map_lookup_elem(&default_deny, &dd_key);

    // there's a default deny. consult the allow list
    if (dd) {
        __u8 *val = bpf_map_lookup_elem(&allowed, &key);
        if (val) {
            return 0;
        }
        return -EPERM;
    }

    __u8 *val = bpf_map_lookup_elem(&banned, &key);
    if (val) {
        return -EPERM;
    }
    return 0;
}

SEC("lsm/generic_handler")
int generic_lsm_handler(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    __u32 key = 0;
    __u8 *argtype = bpf_map_lookup_elem(&argtypes, &key);
    if (!argtype) {
        return 0;
    }

    __u64 *args = (__u64*)ctx;

    __u8 *val = bpf_map_lookup_elem(&cgids, &cgid);
    if (!val) {
        return 0;
    }

    switch (*argtype) {
        case ARGTYPE_FILE_OPEN: {
            return handle_open(args, &cgid);
        }
        case ARGTYPE_EXEC_CHECK: {
            return handle_exec(args, &cgid);
        }
        default: {
            bpf_printk("lsm: unknown argtype=%u", *argtype);
        }
    };

    return 0;
}

char LICENSE[] SEC("license") = "GPL";