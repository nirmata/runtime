// +build ignore

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "maps.h"

static __always_inline __u64 mask_of(void *entries, struct entry *key) {
    __u64 *v = bpf_map_lookup_elem(entries, key);
    return v ? *v : 0;
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

SEC("runtime_policy")
int runtime_policy_executor(void *ctx)
{
    __u32 ctx_key = 0;
    struct policy_ctx *prog_ctx = bpf_map_lookup_elem(&ctx_map, &ctx_key);
    if (!prog_ctx) {
        return 0;
    }

    void *entries = prog_ctx->prog_type == PROG_TYPE_OPEN ? (void *)&open_entries : (void *)&exec_entries;

    struct entry key = { .data_type = CGID };
    __u64 cgid = bpf_get_current_cgroup_id();
    __builtin_memcpy(key.data, &cgid, sizeof(cgid));
    /* read the bitmap that contains which policies target this cgid */
    __u64 cg = mask_of(entries, &key);

    if (cg) {
        __builtin_memset(key.data, 0, sizeof(key.data));
        key.data_type = FLAGS;
        /* check if there is a default deny set by ANY policy */
        __u64 dd = mask_of(entries, &key); 

        bpf_probe_read_kernel(key.data, sizeof(key.data), prog_ctx->path);
        /* read the policy bitmaps for that path. if this path is specified by multiple
         * policies, every bit corresponding to a policy index will be 1 */
        key.data_type = DENY_ENTRY;
        __u64 deny = mask_of(entries, &key);
        key.data_type = ALLOW_ENTRY;
        __u64 allow = mask_of(entries, &key);

        for (int d = 0; d < MAX_PREFIX_DEPTH; d++) {
            if (d >= prog_ctx->nslash) {
                break;
            }
            /* read the length of that path part, stored in prog_ctx->slash[d].
             * then ensure it doesn't exceed MAX_PATH_LEN */
            __u32 len = (prog_ctx->slash[d] & (MAX_PATH_LEN - 1)) + 1;
            __builtin_memset(key.data, 0, sizeof(key.data));
            bpf_probe_read_kernel(key.data, len, prog_ctx->path);
            key.data_type = DENY_PREFIX_ENTRY;
            deny |= mask_of(entries, &key);
            key.data_type = ALLOW_PREFIX_ENTRY;
            allow |= mask_of(entries, &key);
        }

        /* every mask covers all policies holding the entry; masking with the
         * policies that select this cgroup is what scopes them to it */
        deny &= cg;
        allow &= cg;
        dd &= cg;
        prog_ctx->reason = deny ? EXPLICIT_DENY : allow ? EXPLICIT_ALLOW : dd ? IMPLICIT_DENY : IMPLICIT_ALLOW;
    }

    record_path_event(&cgid, prog_ctx->path, prog_ctx->reason);
    if (prog_ctx->reason == IMPLICIT_DENY || prog_ctx->reason == EXPLICIT_DENY) {
        return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
