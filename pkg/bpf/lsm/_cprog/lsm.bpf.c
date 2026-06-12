#include "include/vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 128
#define EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} argtypes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_PATH_LEN]);
    __type(value, __u8);
} banned SEC(".maps");


static __always_inline int handle_open(__u64 *args) {
    __u64 arg0 = args[0];
    struct file *f = (struct file *)arg0;
    char buf[MAX_PATH_LEN] = {};
    bpf_d_path(&f->f_path, buf, sizeof(buf));
    char key[MAX_PATH_LEN] = {};
    bpf_printk("lsm: tail: %x %x %x", buf[MAX_PATH_LEN - 12], buf[MAX_PATH_LEN - 8], buf[MAX_PATH_LEN - 1]);
    bpf_probe_read_kernel_str(key, sizeof(key), buf);

    __u8 *val = bpf_map_lookup_elem(&banned, &key);
    if (val) {
        bpf_printk("lsm: denying open: path=%s", key);
        return -EPERM;
    }
    bpf_printk("lsm: allowing open: path=%s", key);
    return 0;
}

static __always_inline int handle_exec(__u64 *args) {
    __u64 arg0 = args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)arg0;
    char buf[MAX_PATH_LEN] = {};
    const char *fname = BPF_CORE_READ(bprm, filename);
    int len = bpf_probe_read_kernel_str(buf, sizeof(buf), fname);
    if (len <= 0) {
        bpf_printk("lsm: exec: failed to read filename (len=%d)", len);
        return 0;
    }
    __u8 *val = bpf_map_lookup_elem(&banned, &buf);
    if (val) {
        bpf_printk("lsm: denying exec: path=%s", buf);
        return -EPERM;
    }
    bpf_printk("lsm: allowing exec: path=%s", buf);
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
            return handle_open(args);
        }
        case 2: {
            return handle_exec(args);
        }
        default: {
            bpf_printk("lsm: unknown argtype=%llu", *argtype);
        }
    };

    return 0;
}

char LICENSE[] SEC("license") = "GPL";