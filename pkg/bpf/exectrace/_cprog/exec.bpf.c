// +build ignore

// exec.bpf.c — observation-only process execution tracer.
//
// Attach: tracepoint/sched/sched_process_exec. This is the observation half of
// exec visibility; pkg/bpf/lsm's bprm_check_security program is the enforcing
// half. The tracepoint runs after the new mm is installed, so mm->arg_start /
// mm->arg_end already describe the NEW argv — which is the whole point, because
// argv is what identifies a stdio MCP server (`npx @modelcontextprotocol/...`,
// `uvx ...`, `python -m ...`) and the LSM hook does not report it.
//
// Filter (kernel side, per proposal §2.3): the cgroup id must be present in the
// `cgids` map. Without that gate this program would report every exec on the
// node, which on a busy node is thousands per second.
//
// vmlinux.h is generated (bpftool btf dump) and gitignored, exactly like
// pkg/bpf/lsm/_cprog/lsm.bpf.c which includes it the same way. CO-RE reads via
// BPF_CORE_READ keep the task_struct/mm_struct offsets relocatable.

#include "include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&cgids, &cgid)) {
        return 0;
    }

    // The record is far too large for the 512 byte BPF stack, so reserve first
    // and fill in place.
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; // buffer full: lose the observation, never block the exec
    }
    __builtin_memset(e, 0, sizeof(*e));

    e->cgroup_id = cgid;
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = (__u32)BPF_CORE_READ(task, real_parent, tgid);

    // filename comes from the tracepoint's __data_loc field: the low 16 bits are
    // the offset of the string from the start of the context.
    __u32 fname_off = ctx->__data_loc_filename & 0xffff;
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), (void *)((__u8 *)ctx + fname_off));

    // argv lives in user memory between mm->arg_start and mm->arg_end as a run
    // of NUL-terminated strings.
    unsigned long p = BPF_CORE_READ(task, mm, arg_start);
    unsigned long arg_end = BPF_CORE_READ(task, mm, arg_end);

    __u16 count = 0;
#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        if (p == 0 || p >= arg_end) {
            break;
        }
        long n = bpf_probe_read_user_str(&e->argv[i][0], MAX_ARG_LEN, (void *)p);
        if (n <= 0) {
            break;
        }
        count = (__u16)(i + 1);
        // n includes the NUL. An argument longer than MAX_ARG_LEN is truncated
        // by the helper and p then advances only MAX_ARG_LEN, so the next slot
        // holds the tail of the same argument. Accepted limitation: long
        // arguments are reported split rather than dropped, and userspace never
        // sees more than MAX_ARGS slots either way.
        p += (unsigned long)n;
    }
    e->argv_len = count;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// GPL: bpf_probe_read_user_str and bpf_probe_read_kernel_str are GPL-only
// helpers.
char LICENSE[] SEC("license") = "GPL";
