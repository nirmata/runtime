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
    __u32 k = 0;
    __u64 *args = (__u64*)ctx;

    char buf[MAX_PATH_LEN] = {};
    void *target_map;

    struct lsm_ctx *prog_ctx = bpf_map_lookup_elem(&ctx_map, &k);
    if (!prog_ctx) {
        return 0;
    }

    prog_ctx->deny = 0;
    prog_ctx->next_prog_idx = 0;
    prog_ctx->have_executed = 0;
    prog_ctx->reason = IMPLICIT_ALLOW;
    /* the slot still holds the previous event's path; the tail after the new
     * string must be zeros or it splits hash keys derived from it */
    __builtin_memset(prog_ctx->path, 0, sizeof(prog_ctx->path));    

    #if defined(LSM_FILE_OPEN)
        struct file *f = (struct file *)args[0];
        prog_ctx->prog_type = PROG_TYPE_LSM_OPEN;

        /* we have no programs, don't proceed */
        __u32 pt = prog_ctx->prog_type;
        __u8 *prog_cnt = bpf_map_lookup_elem(&prog_count, &pt);
        if (!prog_cnt || *prog_cnt == 0) {
            return 0;
        }

        bpf_d_path(&f->f_path, buf, sizeof(buf));
        bpf_probe_read_kernel_str(prog_ctx->path, sizeof(prog_ctx->path), buf);

        target_map = &open_progs;
    #elif defined(LSM_EXEC_CHECK)
        struct linux_binprm *bprm = (struct linux_binprm *)args[0];
        prog_ctx->prog_type = PROG_TYPE_LSM_EXEC;

         /* we have no programs, don't proceed */
        __u32 pt = prog_ctx->prog_type;
        __u8 *prog_cnt = bpf_map_lookup_elem(&prog_count, &pt);
        if (!prog_cnt || *prog_cnt == 0) {
            return 0;
        }

        bpf_d_path(&bprm->file->f_path, buf, sizeof(buf));
        bpf_probe_read_kernel_str(prog_ctx->path, sizeof(prog_ctx->path), buf);

        target_map = &exec_progs;
    #endif

    for (int i = 0; i < MAX_PROG_COUNT; i++ ){
        bpf_tail_call(ctx, target_map, prog_ctx->next_prog_idx);
        prog_ctx->next_prog_idx++;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
