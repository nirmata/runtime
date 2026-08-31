#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

#if !defined(LSM_FILE_OPEN) && !defined(LSM_EXEC_CHECK)
#error "must build dispatcher.c with exactly one of -DLSM_FILE_OPEN or -DLSM_EXEC_CHECK defined"
#endif

#if defined(LSM_FILE_OPEN) && defined(LSM_EXEC_CHECK)
#error "must build dispatcher.c with exactly one of -DLSM_FILE_OPEN or -DLSM_EXEC_CHECK defined"
#endif

SEC("lsm/generic_handler")
int generic_lsm_handler(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 *args = (__u64*)ctx;

    char buf[MAX_PATH_LEN] = {};
    void *target_map;

    struct policy_ctx *prog_ctx = task_ctx();
    if (!prog_ctx) {
        return 0;
    }

    prog_ctx->reason = IMPLICIT_ALLOW;
    /* the slot still holds the previous event's path; the tail after the new
     * string must be zeros or it splits hash keys derived from it */
    __builtin_memset(prog_ctx->path, 0, sizeof(prog_ctx->path));    

    #if defined(LSM_FILE_OPEN)
        struct file *f = (struct file *)args[0];
        bpf_d_path(&f->f_path, buf, sizeof(buf));
        bpf_probe_read_kernel_str(prog_ctx->path, sizeof(prog_ctx->path), buf);

        target_map = &open_prog;
        prog_ctx->prog_type = PROG_TYPE_OPEN; /* we set this because we wanna look up the policy count */
    #elif defined(LSM_EXEC_CHECK)
        struct linux_binprm *bprm = (struct linux_binprm *)args[0];
        bpf_d_path(&bprm->file->f_path, buf, sizeof(buf));
        bpf_probe_read_kernel_str(prog_ctx->path, sizeof(prog_ctx->path), buf);

        target_map = &exec_prog;
        prog_ctx->prog_type = PROG_TYPE_EXEC;
    #endif

    /* jump to the policy enforcer */
    bpf_tail_call(ctx, target_map, 0 );

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
