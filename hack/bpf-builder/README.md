# bpf-builder

Container image that compiles the eBPF objects under `pkg/bpf/*/_cprog` via
`bpf2go`. Developer hosts (darwin) have no clang with a BPF target, so both
`make generate-bpf` and the CI drift gate (`make verify-bpf`) run generation
inside this image.

## The clang version is the reproducibility contract

clang compiles with `-target bpfel` / `-target bpfeb`, so the image and host
architecture never influence the emitted bytecode -- only the clang version
does (instruction selection, BTF encoding, and which local symbols survive
`llvm-strip` all change between releases). `make verify-bpf` recompiles the
committed C with this image and fails on any byte difference, which is only a
meaningful check because everyone -- every developer and CI -- compiles with the
same pinned clang. Bump `BPF_CLANG` in the Dockerfile deliberately, regenerate
every object with `make generate-bpf`, and commit the Dockerfile change and all
regenerated objects together.

## Why `vmlinux.h` is minimal and committed, not generated

`pkg/bpf/include/vmlinux.h` is a small, hand-maintained header, not
the output of `bpftool btf dump file /sys/kernel/btf/vmlinux format c`. The
full dump is ~3 MB / ~153k lines and describes whatever kernel the builder
host happens to run, so generating it at build time makes the objects differ
from host to host -- the drift check would pass locally and fail in CI.

Committing a minimal header is safe because every struct in it carries
`__attribute__((preserve_access_index))`: clang records each kernel-struct
field access as a CO-RE relocation *by field name*, and libbpf patches the real
offset from the running kernel's BTF at load time. The compile-time layouts in
the header are placeholders; only the field names on the access path matter.
This was validated by building the LSM programs against both a full generated
header and the minimal one: the instruction streams are identical except for
the relocation placeholder immediates, and the CO-RE records target the same
`file.f_path` / `linux_binprm.file` fields.

If the C grows a new kernel-struct access, add just that struct (and the fields
on the access path) to the minimal header, keep `preserve_access_index`, and
regenerate.

## Regenerating after changing the C

```sh
make generate-bpf   # rebuilds the image if needed, regenerates *_bpfe{l,b}.{go,o}
make verify-bpf     # what CI runs: regenerate + git diff --exit-code
```

Commit the changed `.c`/`.h` files together with all regenerated objects;
`verify-bpf` in CI rejects a PR that changes one without the other.
