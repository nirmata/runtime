#ifndef FNV1A_H
#define FNV1A_H

#include <bpf/bpf_core_read.h>   // safe primitive types in BPF context

#define FNV1A_32_INIT  0x811c9dc5u
#define FNV1A_32_PRIME 0x01000193u

#define MAX_LEN 128

static __always_inline __u32 fnv1a_32(const char *p, __u32 len)
{
    __u32 hash = FNV1A_32_INIT;

#pragma unroll
    for (__u32 i = 0; i < MAX_LEN; i++) {
        if (i >= len)
            break;

        hash ^= p[i];
        hash *= FNV1A_32_PRIME;
    }

    return hash;
}

#endif