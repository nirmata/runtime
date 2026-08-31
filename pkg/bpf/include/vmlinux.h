/* Minimal, hand-maintained stand-in for a bpftool-generated vmlinux.h, shared
 * by every program under the per-package _cprog directories.
 *
 * A full `bpftool btf dump file /sys/kernel/btf/vmlinux format c` header is
 * ~3 MB and reflects whatever kernel the builder host happens to run, which
 * makes the committed objects unreproducible across hosts. This file instead
 * declares only the kernel types those programs actually use.
 *
 * Correctness does not depend on the layouts below matching any particular
 * kernel: every struct is marked __attribute__((preserve_access_index)), so
 * clang records each field access as a CO-RE relocation *by field name* and
 * libbpf patches the real offset from the running kernel's BTF at load time.
 * The compile-time offsets here are placeholders.
 *
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
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
};

/* bpf_map_update_elem flags (kernel anonymous enum). */
enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

/* bpf_attr map_flags. Task storage rejects a preallocated map. */
enum {
	BPF_F_NO_PREALLOC = (1U << 0),
};

/* bpf_task_storage_get flags. */
enum {
	BPF_LOCAL_STORAGE_GET_F_CREATE = (1ULL << 0),
};

/* Opaque handle returned by map-in-map lookups; never dereferenced. */
struct bpf_map;

/* Context for SEC("lsm/...") and SEC("raw_tp/...") programs; accessed only via
 * a cast, so the flexible array member is declaration-of-record rather than
 * load-bearing. */
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
	unsigned int f_flags; /* carries __FMODE_EXEC on the open of a binary (CO-RE) */
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct file *file; /* bprm->file read in the bprm_check hook (CO-RE) */
	int argc;
	const char *filename;
} __attribute__((preserve_access_index));

/* arg_start begins the run of NUL-separated argv strings in the new mm. */
struct mm_struct {
	unsigned long arg_start;
} __attribute__((preserve_access_index));

struct task_struct {
	struct mm_struct *mm;
} __attribute__((preserve_access_index));

#define SIGKILL 9
#define SIGTERM 15

#endif /* __VMLINUX_H__ */
