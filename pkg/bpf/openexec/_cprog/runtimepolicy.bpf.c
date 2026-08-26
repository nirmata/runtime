// +build ignore

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

/* never used as declared: the loader replaces it with the prog array of the
 * hook this instance chains from, so the program itself references no
 * hook-specific map and stays loadable for any attach target */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_PROG_COUNT);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} chain_progs SEC(".maps");

// The policy maps are keyed by char[MAX_PATH_LEN], hence key->path rather than
// the whole event key. ctx is shared by every program in the tail-call chain,
// so the reason/deny it carries in may already hold an earlier program's
// verdict: an explicit allow set by another policy overrides implicit deny.
static __always_inline void path_decision(struct lsm_ctx *ctx, struct path_event_key *key) {
    __u32 dd_key = 0;
    __u8 *dd = bpf_map_lookup_elem(&default_deny, &dd_key);

    /* a 128-byte __builtin_memcpy is past clang's inline-expansion limit and
     * becomes a memcpy call the BPF backend cannot emit */
    bpf_probe_read_kernel(key->path, sizeof(key->path), ctx->path);


    if (bpf_map_lookup_elem(&banned, key->path) != NULL) {
        ctx->deny = 1;
        ctx->reason = EXPLICIT_DENY;
        goto out;
    }

    if (bpf_map_lookup_elem(&allowed, key->path) != NULL) {
        ctx->deny = 0;
        ctx->reason = EXPLICIT_ALLOW;
        goto out;
    }

    if (dd && ctx->reason != EXPLICIT_ALLOW) {
        ctx->deny = 1;
        ctx->reason = IMPLICIT_DENY;
    }

out:
    key->decision = ctx->deny ? DECISION_DENY : DECISION_ALLOW;
}

static __always_inline void record_path_event(__u64 *cgid, struct path_event_key *key) {
    struct bpf_map *count_map = bpf_map_lookup_elem(&open_events, cgid);
    if (!count_map) {
        return;
    }

    __u32 *count = bpf_map_lookup_elem(count_map, key);
    if (count) {
        __sync_fetch_and_add(count, 1);
        return;
    }

    __u32 init_count = 1;
    if (bpf_map_update_elem(count_map, key, &init_count, BPF_NOEXIST) != 0) {
        // lost the create race with another CPU: the entry exists now, add to it
        count = bpf_map_lookup_elem(count_map, key);
        if (count) {
            __sync_fetch_and_add(count, 1);
            return;
        }
        __u32 stat = PATH_STAT_COUNT_MAP_FULL;
        __u64 *v = bpf_map_lookup_elem(&stats, &stat);
        if (v) {
            *v += 1; // per-CPU value, so no atomic
        }
    }
}


SEC("runtime_policy")
int runtime_policy_executor(void *ctx)
{
    __u32 k = 0;
    struct path_event_key ev_k = {};

    struct lsm_ctx *prog_ctx = bpf_map_lookup_elem(&ctx_map, &k);
    if (!prog_ctx) {
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();
    if (bpf_map_lookup_elem(&cgids, &cgid) != NULL) {
        path_decision(prog_ctx, &ev_k);
        if (prog_ctx->reason == EXPLICIT_DENY) {
            goto end;
        }
    }

    prog_ctx->have_executed++;

    __u32 pt = prog_ctx->prog_type;
    __u8 *pc = bpf_map_lookup_elem(&prog_count, &pt);
    if (!pc || *pc <= prog_ctx->have_executed) {
        goto end;
    }

    for (int i = 0; i < MAX_PROG_COUNT; i++) {
        /* advance past this program's own slot first: tail-calling
         * next_prog_idx as-is would re-enter the running program */
        prog_ctx->next_prog_idx++;
        bpf_tail_call(ctx, &chain_progs, prog_ctx->next_prog_idx);
    }

end:
    /* reached with fewer than prog_count programs executed when userspace
     * deleted a program we counted. no synchronization needed: return what
     * the programs that did run decided. */
    record_path_event(&cgid, &ev_k);
    if (prog_ctx->deny) {
        /* the policy program was reached from a tracepoint dispatcher */
        if (prog_ctx->should_pkill) {
            long ret = bpf_send_signal(SIGKILL);
            return 0;
        }
        return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
