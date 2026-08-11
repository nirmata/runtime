#ifndef NIRMATA_RUNTIME_DNSNAME_H
#define NIRMATA_RUNTIME_DNSNAME_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* The wire-format QNAME, lowercased and zero padded; userspace interns policy
 * names into these exact bytes. */
#define MAX_DOMAIN_LEN 128

/* Both high bits set is a compression pointer; either alone is reserved. */
#define DNS_LABEL_PTR 0xc0

struct domain_key {
    __u8 name[MAX_DOMAIN_LEN];
};

/* One flat pass instead of a loop per label: `remaining` counts down the current
 * label, so a byte read with remaining == 0 is the next length byte, and the
 * verifier sees a single unrolled loop with constant indices. key must be zeroed
 * by the caller: the terminating zero byte is the padding, never written, and
 * qname_len counts it. bpf_skb_load_bytes because an skb may be non-linear. */
static __always_inline int read_qname(struct __sk_buff *skb, __u32 off,
                                      struct domain_key *key, __u32 *qname_len)
{
    __u32 remaining = 0;
    __u8 b;

#pragma unroll
    for (__u32 i = 0; i < MAX_DOMAIN_LEN; i++) {
        if (bpf_skb_load_bytes(skb, off + i, &b, sizeof(b)) < 0)
            return -1;

        if (remaining == 0) {
            if (b == 0) {
                *qname_len = i + 1;
                return 0;
            }
            if (b & DNS_LABEL_PTR)
                return -1;
            remaining = b;
        } else {
            if (b >= 'A' && b <= 'Z')
                b += 'a' - 'A';
            remaining--;
        }

        key->name[i] = b;
    }

    return -1;
}

#endif /* NIRMATA_RUNTIME_DNSNAME_H */
