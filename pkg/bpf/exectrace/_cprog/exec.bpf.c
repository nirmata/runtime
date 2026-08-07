// +build ignore

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

// Recycled ring buffer memory still holds the previous record, which would
// leak one pod's argv into another's event. Volatile stores: clang rejects a
// __builtin_memset this large and folds a plain store loop back into one.
static __always_inline void zero_event(struct exec_event *e)
{
    volatile __u64 *w = (volatile __u64 *)e;
#pragma clang loop unroll(full)
    for (int i = 0; i < (int)(sizeof(*e) / sizeof(__u64)); i++) {
        w[i] = 0;
    }
}

SEC("raw_tp/sched_process_exec")
int trace_exec(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&cgids, &cgid)) {
        return 0;
    }

    // raw tracepoint args are (task, old_pid, bprm); old_pid is the pid the
    // task had before the exec, which nothing here needs.
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    // too large for the 512 byte BPF stack, so reserve first and fill in place
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __u32 stat = STAT_RINGBUF_FULL;
        __u64 *v = bpf_map_lookup_elem(&stats, &stat);
        if (v) {
            *v += 1; // per-CPU value, so no atomic
        }
        return 0; // never block the exec
    }
    zero_event(e);

    e->cgroup_id = cgid;
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), filename);

    int argc = BPF_CORE_READ(bprm, argc);
    if (argc < 0) {
        argc = 0;
    }
    if (argc > MAX_ARGS) {
        argc = MAX_ARGS;
        __u32 stat = STAT_ARGV_OVERFLOW;
        __u64 *v = bpf_map_lookup_elem(&stats, &stat);
        if (v) {
            *v += 1;
        }
    }

    // argv is a run of NUL-terminated strings starting at mm->arg_start
    unsigned long p = BPF_CORE_READ(task, mm, arg_start);

    // left unrolled: the argc bound is dynamic
    __u16 count = 0;
    for (int i = 0; i < MAX_ARGS; i++) {
        if (i >= argc) {
            break;
        }
        if (p == 0) {
            break;
        }
        long n = bpf_probe_read_user_str(&e->argv[i][0], MAX_ARG_LEN, (void *)p);
        if (n <= 0) {
            break;
        }
        count = (__u16)(i + 1);
        p += (unsigned long)n;
    }
    if (count < argc) {
        __u32 stat = STAT_ARGV_UNREADABLE;
        __u64 *v = bpf_map_lookup_elem(&stats, &stat);
        if (v) {
            *v += 1;
        }
    }
    e->argv_len = count;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// bpf_probe_read_user_str and bpf_probe_read_kernel_str are GPL-only.
char LICENSE[] SEC("license") = "GPL";
