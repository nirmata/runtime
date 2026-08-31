#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

/* fs.h sets this in f_flags for the open the kernel performs on a binary it is
 * about to execute. It is a macro, so vmlinux.h does not carry it. */
#define __FMODE_EXEC 0x20

SEC("fmod_ret/security_file_open")
int generic_tracepoint_handler(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 k = 0;
    __u64 *args = (__u64*)ctx;

    char buf[MAX_PATH_LEN] = {};
    void *target_map;

    struct policy_ctx *prog_ctx = bpf_map_lookup_elem(&ctx_map, &k);
    if (!prog_ctx) {
        return 0;
    }

    prog_ctx->reason = IMPLICIT_ALLOW;
    /* the slot still holds the previous event's path; the tail after the new
     * string must be zeros or it splits hash keys derived from it */
    __builtin_memset(prog_ctx->path, 0, sizeof(prog_ctx->path));

    struct file *f = (struct file *)args[0];
    bpf_d_path(&f->f_path, buf, sizeof(buf));
    bpf_probe_read_kernel_str(prog_ctx->path, sizeof(prog_ctx->path), buf);

    if (BPF_CORE_READ(f, f_flags) & __FMODE_EXEC) {
        target_map = &exec_prog;
        prog_ctx->prog_type = PROG_TYPE_EXEC;
    } else {
        target_map = &open_prog;
        prog_ctx->prog_type = PROG_TYPE_OPEN;
    }

    /* jump to the policy enforcer */
    bpf_tail_call(ctx, target_map, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
