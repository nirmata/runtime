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

/* Single pass over the wire-format QNAME, copying bytes into key->name (lowercased)
* up to MAX_DOMAIN_LEN. Compression pointers are not supported and are rejected. */
static __always_inline int read_qname(struct __sk_buff *skb, __u32 off,
                                      struct domain_key *key, __u32 *qname_len)
{
    __u32 remaining = 0;
    __u8 b;

#pragma unroll
    for (__u32 i = 0; i < MAX_DOMAIN_LEN; i++) {
        if (bpf_skb_load_bytes(skb, off + i, &b, sizeof(b)) < 0)
            return -1;

        /*
         * we either must be at the end, or have a compression pointer
         * that indicates the length. set that to remaining
         */
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
