#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

#if !defined(TRACE_FILE_OPEN) && !defined(TRACE_EXEC_CHECK)
#error "must build trace.dispatcher.c with exactly one of -DTRACE_FILE_OPEN or -DTRACE_EXEC_CHECK defined"
#endif

#if defined(TRACE_FILE_OPEN) && defined(TRACE_EXEC_CHECK)
#error "must build trace.dispatcher.c with exactly one of -DTRACE_FILE_OPEN or -DTRACE_EXEC_CHECK defined"
#endif

struct trace_event_raw_sys_enter {
    unsigned long long pad;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/syscalls/generic_tracepoint")
int generic_tracepoint_handler(struct trace_event_raw_sys_enter *ctx) {
    __u32 k = 0;

    void *target_map;

    struct lsm_ctx *prog_ctx = bpf_map_lookup_elem(&ctx_map, &k);
    if (!prog_ctx) {
        return 0;
    }

    prog_ctx->deny = 0;
    prog_ctx->next_prog_idx = 0;
    prog_ctx->have_executed = 0;
    prog_ctx->reason = IMPLICIT_ALLOW;
    prog_ctx->should_pkill = 1;
    /* the slot still holds the previous event's path; the tail after the new
     * string must be zeros or it splits hash keys derived from it */
    __builtin_memset(prog_ctx->path, 0, sizeof(prog_ctx->path));    

    #if defined(TRACE_FILE_OPEN)
        /* sys_enter_openat: (int dfd, const char __user *filename, int flags, umode_t mode) */
        int dfd = (int)ctx->args[0];
        const char *filename = (const char *)ctx->args[1];
        prog_ctx->prog_type = PROG_TYPE_LSM_OPEN;

        /* we have no programs, don't proceed */
        __u8 *prog_cnt = bpf_map_lookup_elem(&prog_count, &prog_ctx->prog_type);
        if (!prog_cnt || *prog_cnt == 0) {
            return 0;
        }

        bpf_probe_read_user_str(prog_ctx->path, sizeof(prog_ctx->path), filename);
        bpf_printk("trace_dispatcher: open path=%s progs=%d", prog_ctx->path, *prog_cnt);

        target_map = &open_progs;
    #elif defined(TRACE_EXEC_CHECK)
        /* sys_enter_execve: (const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp) */
        const char *filename = (const char *)ctx->args[0];
        prog_ctx->prog_type = PROG_TYPE_LSM_EXEC;

        /* we have no programs, don't proceed */
        __u8 *prog_cnt = bpf_map_lookup_elem(&prog_count, &prog_ctx->prog_type);
        if (!prog_cnt || *prog_cnt == 0) {
            return 0;
        }

        bpf_probe_read_user_str(prog_ctx->path, sizeof(prog_ctx->path), filename);
        bpf_printk("trace_dispatcher: exec path=%s progs=%d", prog_ctx->path, *prog_cnt);

        target_map = &exec_progs;
    #endif

    for (int i = 0; i < MAX_PROG_COUNT; i++ ){
        bpf_tail_call(ctx, target_map, prog_ctx->next_prog_idx);
        prog_ctx->next_prog_idx++;
    }

    return 0;
}

/* bpf_probe_read_user_str is GPL-only. */
char LICENSE[] SEC("license") = "GPL";
