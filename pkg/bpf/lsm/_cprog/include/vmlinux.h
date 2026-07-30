/* Minimal, hand-maintained stand-in for a bpftool-generated vmlinux.h.
 *
 * A full `bpftool btf dump file /sys/kernel/btf/vmlinux format c` header is
 * ~3 MB and reflects whatever kernel the builder host happens to run, which
 * makes the committed objects unreproducible across hosts. This file instead
 * declares only the kernel types lsm.bpf.c and maps.h actually use.
 *
 * Correctness does not depend on the layouts below matching any particular
 * kernel: every struct is marked __attribute__((preserve_access_index)), so
 * clang records each field access as a CO-RE relocation *by field name* and
 * libbpf patches the real offset from the running kernel's BTF at load time.
 * The compile-time offsets here are placeholders.
 *
 * If lsm.bpf.c grows a new kernel-struct access, add just that struct (and the
 * fields on the access path) here, keep preserve_access_index, and run
 * `make generate-bpf`.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef signed char __s8;
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

/* Map types used in maps.h (kernel enum bpf_map_type values). */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
};

/* bpf_map_update_elem flags (kernel anonymous enum). */
enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

/* Opaque handle returned by map-in-map lookups; never dereferenced. */
struct bpf_map;

/* Context for SEC("lsm/...") programs; accessed only via a cast, so the
 * flexible array member is declaration-of-record rather than load-bearing. */
struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

struct dentry;
struct vfsmount;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path; /* &f->f_path passed to bpf_d_path (CO-RE) */
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct file *file; /* bprm->file read in the bprm_check hook (CO-RE) */
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */
