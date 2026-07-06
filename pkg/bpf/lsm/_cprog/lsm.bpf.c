// +build ignore

#include "include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

// TODO: how do avoid defining those twice
#define DEFAULT_DENY 1
#define LEARNING_MODE 2


static __always_inline int handle_open(__u64 *args, __u8 cgid_map_val) {
    __u64 arg0 = args[0];
    struct file *f = (struct file *)arg0;
    char buf[MAX_PATH_LEN] = {};
    bpf_d_path(&f->f_path, buf, sizeof(buf));

    char key[MAX_PATH_LEN] = {};
    bpf_probe_read_kernel_str(key, sizeof(key), buf); 


    if (cgid_map_val) {
        __u32 *open_count = bpf_map_lookup_elem(&open_events, &key);
        if (open_count) {
            (*open_count)++;
        } else {
            __u32 init_count = 1;
            bpf_map_update_elem(&open_events, &key, &init_count, BPF_ANY);
        };
    }

    __u8 *dd_key = 0;
   __u8 *dd = bpf_map_lookup_elem(&default_deny, dd_key);

    // there's a default deny. consult the allow list
    if (dd) {
        __u8 *val = bpf_map_lookup_elem(&allowed, &key);
        if (val) {
            bpf_printk("lsm: allowing open: path=%s", key);
            return 0;
        }
        bpf_printk("lsm: denying open: path=%s", key);
        return -EPERM;
    }

    __u8 *val = bpf_map_lookup_elem(&banned, &key);
    if (val) {
        bpf_printk("lsm: denying open: path=%s", key);
        return -EPERM;
    }
    bpf_printk("lsm: allowing open: path=%s", key);
    return 0;
}

static __always_inline int handle_exec(__u64 *args, __u8 cgid_map_val) {
    __u64 arg0 = args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)arg0;
    char key[MAX_PATH_LEN] = {};
    const char *fname = BPF_CORE_READ(bprm, filename);
    int len = bpf_probe_read_kernel_str(key, sizeof(key), fname);
    if (len <= 0) {
        bpf_printk("lsm: exec: failed to read filename (len=%d)", len);
        return 0;
    }

    if (cgid_map_val) {
        __u32 *open_count = bpf_map_lookup_elem(&open_events, &key);
        if (open_count) {
            (*open_count)++;
        } else {
            __u32 init_count = 1;
            bpf_map_update_elem(&open_events, &key, &init_count, BPF_ANY);
        };
    }

    __u8 *dd_key = 0;
    __u8 *dd = bpf_map_lookup_elem(&default_deny, dd_key);

    // there's a default deny. consult the allow list
    if (dd) {
        __u8 *val = bpf_map_lookup_elem(&allowed, &key);
        if (val) {
            bpf_printk("lsm: allowing exec: path=%s", key);
            return 0;
        }
        bpf_printk("lsm: denying exec: path=%s", key);
        return -EPERM;
    }

    __u8 *val = bpf_map_lookup_elem(&banned, &key);
    if (val) {
        bpf_printk("lsm: denying exec: path=%s", key);
        return -EPERM;
    }
    bpf_printk("lsm: allowing exec: path=%s", key);
    return 0;
}

SEC("lsm/generic_handler")
int generic_lsm_handler(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    __u32 key = 0;
    __u64 *argtype = bpf_map_lookup_elem(&argtypes, &key);
    if (!argtype) {
        bpf_printk("lsm: no argtype configured, skipping");
        return 0;
    }

    __u64 *args = (__u64*)ctx;

    __u8 *val = bpf_map_lookup_elem(&cgids, &cgid);
    if (!val) {
        return 0;
    }
 
    bpf_printk("lsm: handler triggered: cgid=%llu argtype=%llu", cgid, *argtype);

    switch (*argtype) {
        case 1: {
            return handle_open(args, *val);
        }
        case 2: {
            return handle_exec(args, *val);
        }
        default: {
            bpf_printk("lsm: unknown argtype=%llu", *argtype);
        }
    };

    return 0;
}

char LICENSE[] SEC("license") = "GPL";