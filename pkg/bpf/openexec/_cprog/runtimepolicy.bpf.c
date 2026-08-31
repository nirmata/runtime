// +build ignore

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

static __always_inline void path_decision(struct policy_entry_map *pm, struct policy_ctx *ctx, struct entry *key) {
    key->data_type = FLAGS;
    __builtin_memset(key->data, 0, sizeof(key->data));

    __u8 *dd = bpf_map_lookup_elem(pm, key);

    /* a 128-byte __builtin_memcpy is past clang's inline-expansion limit and
     * becomes a memcpy call the BPF backend cannot emit */
    bpf_probe_read_kernel(key->data, sizeof(key->data), ctx->path);

    /* try to check if its in the deny entries*/
    key->data_type = DENY_ENTRY;

    if (bpf_map_lookup_elem(pm, key) != NULL) {
        ctx->reason = EXPLICIT_DENY;
        return;
    }

    key->data_type = ALLOW_ENTRY;

    if (bpf_map_lookup_elem(pm, key) != NULL) {
        ctx->reason = EXPLICIT_ALLOW;
        return;
    }

    if (dd) {
        ctx->reason = IMPLICIT_DENY;
    }

    bpf_printk("verdict reason=%d path=%s", ctx->reason, ctx->path);
}

static __always_inline void record_path_event(__u64 *cgid, char buf[MAX_PATH_LEN], enum decision_reason des) {
    struct bpf_map *count_map = bpf_map_lookup_elem(&events_map, cgid);
    if (!count_map) {
        return;
    }

    struct path_event_key k;
    bpf_probe_read_kernel(k.path, sizeof(k.path), buf);
    k.decision = (des == EXPLICIT_DENY || des == IMPLICIT_DENY) ? DECISION_DENY : DECISION_ALLOW;

    __u32 *count = bpf_map_lookup_elem(count_map, &k);
    if (count) {
        __sync_fetch_and_add(count, 1);
        return;
    }

    __u32 init_count = 1;
    if (bpf_map_update_elem(count_map, &k, &init_count, BPF_NOEXIST) != 0) {
        // lost the create race with another CPU: the entry exists now, add to it
        count = bpf_map_lookup_elem(count_map, &k);
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

static __always_inline struct policy_entry_map *policy_map_for(__u8 prog_type, int i) {
    if (prog_type == PROG_TYPE_OPEN) {
        return bpf_map_lookup_elem(&open_policies, &i);
    }
    return bpf_map_lookup_elem(&exec_policies, &i);
}

SEC("runtime_policy")
int runtime_policy_executor(void *ctx)
{
    /* the same task the dispatcher ran in, so this is the slot it just wrote */
    struct policy_ctx *prog_ctx = task_ctx();
    if (!prog_ctx) {
        return 0;
    }

    /* no policies, do nothing */
    __u32 prog_key = prog_ctx->prog_type;
    __u8 *pc = bpf_map_lookup_elem(&prog_count, &prog_key);
    if (!pc || *pc == 0) {
        return 0;
    } 

    __u64 cgid = bpf_get_current_cgroup_id();
    for (int i = 0; i < MAX_PROG_COUNT; i++) {
        struct policy_entry_map *pm = policy_map_for(prog_ctx->prog_type, i);
        if (!pm) {
            continue;
        };

        struct entry *k = &(struct entry) {
            .data_type = CGID,   
        };

        __builtin_memcpy(k->data, &cgid, sizeof(cgid));
        __u8 *exists = bpf_map_lookup_elem(pm, k);
        if (!exists) {
            continue;
        }

        /* every policy is evaluated on its own: an allow in one policy must not
         * survive into the next one's default-deny, so a deny from any single
         * policy is final */
        prog_ctx->reason = IMPLICIT_ALLOW;
        path_decision(pm, prog_ctx, k);
        if (prog_ctx->reason == EXPLICIT_DENY || prog_ctx->reason == IMPLICIT_DENY) {
            goto end;
        }
    };

end:
    record_path_event(&cgid, prog_ctx->path, prog_ctx->reason);
    if (prog_ctx->reason == IMPLICIT_DENY || prog_ctx->reason == EXPLICIT_DENY) {
        return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
