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

#if defined(TRACE_FILE_OPEN)
#define HOOK_SEC "fmod_ret/security_file_open"
#else
#define HOOK_SEC "fmod_ret/security_bprm_check"
#endif

SEC(HOOK_SEC)
int generic_tracepoint_handler(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 k = 0;
    __u64 *args = (__u64*)ctx;

    void *target_map;

    struct policy_ctx *prog_ctx = bpf_map_lookup_elem(&ctx_map, &k);
    if (!prog_ctx) {
        return 0;
    }

    prog_ctx->reason = IMPLICIT_ALLOW;
    /* the slot still holds the previous event's path; the tail after the new
     * string must be zeros or it splits hash keys derived from it */
    __builtin_memset(prog_ctx->path, 0, sizeof(prog_ctx->path));

    #if defined(TRACE_FILE_OPEN)
        char buf[MAX_PATH_LEN] = {};
        struct file *f = (struct file *)args[0]; 
        bpf_d_path(&f->f_path, buf, sizeof(buf));
        bpf_probe_read_kernel_str(prog_ctx->path, sizeof(prog_ctx->path), buf);

        target_map = &open_prog;
        prog_ctx->prog_type = PROG_TYPE_OPEN;
    #elif defined(TRACE_EXEC_CHECK)
        /* bpf_d_path is not allowlisted for security_bprm_check; bprm->filename
         * is the kernel's own copy of the exec path, so unlike a sys_enter read
         * it cannot be rewritten by another thread after the check */
        struct linux_binprm *bprm = (struct linux_binprm *)args[0];
        const char *filename = BPF_CORE_READ(bprm, filename);
        bpf_probe_read_kernel_str(prog_ctx->path, sizeof(prog_ctx->path), filename);

        target_map = &exec_prog;
        prog_ctx->prog_type = PROG_TYPE_EXEC;
    #endif

    /* jump to the policy enforcer */
    bpf_tail_call(ctx, target_map, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
