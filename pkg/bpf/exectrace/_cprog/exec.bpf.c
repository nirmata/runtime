// +build ignore

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

// Observation-only process execution tracer. pkg/bpf/lsm's bprm_check_security
// program is the enforcing half; this one reports argv, which is what
// identifies a stdio MCP server (`npx @modelcontextprotocol/...`, `uvx ...`)
// and which the LSM hook does not carry.
//
// sched_process_exec is taken as a raw tracepoint rather than through its
// ftrace format, because the raw form passes `struct linux_binprm *` as its
// third argument and the fixed format does not. bprm->argc is the only
// trustworthy bound on the argv walk below: mm->arg_end brackets argv and envp
// together on some kernels, so a loop that stops at arg_end runs off the end of
// argv and reports environment strings as arguments.

static __always_inline void bump(__u32 stat)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &stat);
    if (v) {
        *v += 1; // per-CPU value, so no atomic
    }
}

// Ring buffer memory is recycled and arrives holding the previous record on
// this CPU. Every byte reaches userspace, so a partly-filled record leaks one
// pod's argv into another's event. clang rejects a __builtin_memset this large
// and folds a plain store loop back into one, so the stores are volatile.
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

    struct task_struct *task = (struct task_struct *)ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    // Too large for the 512 byte BPF stack, so reserve first and fill in place.
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump(STAT_RINGBUF_FULL);
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
        bump(STAT_ARGV_OVERFLOW);
    }

    // argv is a run of NUL-terminated strings starting at mm->arg_start.
    unsigned long p = BPF_CORE_READ(task, mm, arg_start);

    // Left rolled: the argc bound is dynamic, so clang cannot unroll it, and
    // the verifier proves the argv[i] store in bounds from the MAX_ARGS trip
    // count without help.
    __u16 count = 0;
    for (int i = 0; i < MAX_ARGS; i++) {
        if (i >= argc) {
            break;
        }
        if (p == 0) {
            break;
        }
        // An argument longer than MAX_ARG_LEN is truncated by the helper, which
        // then returns MAX_ARG_LEN and leaves p short of the next argument; the
        // following slot holds the tail of the same argument. Reported split
        // rather than dropped.
        long n = bpf_probe_read_user_str(&e->argv[i][0], MAX_ARG_LEN, (void *)p);
        if (n <= 0) {
            break;
        }
        count = (__u16)(i + 1);
        p += (unsigned long)n;
    }
    if (count < argc) {
        bump(STAT_ARGV_UNREADABLE);
    }
    e->argv_len = count;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// bpf_probe_read_user_str and bpf_probe_read_kernel_str are GPL-only.
char LICENSE[] SEC("license") = "GPL";
