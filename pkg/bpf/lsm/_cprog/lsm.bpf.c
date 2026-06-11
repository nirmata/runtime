#include "include/vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 128
#define EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
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
    struct file *f = (struct file *)arg0; // cast arg0 to a file
    char buf[MAX_PATH_LEN] = {};
    bpf_d_path(&f->f_path, buf, sizeof(buf));

    __u8 *val = bpf_map_lookup_elem(&banned, &buf);
    if (val) {
        return -EPERM;
    }
    return 0;
}

static __always_inline int handle_exec(__u64 *args) {
    __u64 arg0 = args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)arg0; // cast arg0 to a binprm
    char buf[MAX_PATH_LEN] = {};  // zero initialized, padding is automatic
    const char *fname = BPF_CORE_READ(bprm, filename);
    int len = bpf_probe_read_kernel_str(buf, sizeof(buf), fname);
    if (len <= 0)
        return 0;
    __u8 *val = bpf_map_lookup_elem(&banned, buf);
    if (val)
        return -EPERM;

    return 0;
}

SEC("lsm/generic_handler")
int generic_lsm_handler(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 cgid = bpf_get_current_pid_tgid() >> 32;
    __u64 *argtype = bpf_map_lookup_elem(&argtypes, 0);
    __u64 *args = (__u64*)ctx; // cast context as a pointer to a u64 (array) 
    // how does tetragon in userspace interpret what the kernel passed ?

    // the cgroup ID that triggered the hook is not targeted by this policy
    __u8 *val = bpf_map_lookup_elem(&cgids, &cgid);
    if (!val) {
        return 0;
    }

    switch (*argtype) {
        case 1: {
            return handle_open(args);
        }
        case 2: {
            return handle_exec(args);
        }
    };    

    return 0;
}

char LICENSE[] SEC("license") = "GPL";