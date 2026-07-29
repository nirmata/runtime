# Builder image for the eBPF objects under pkg/bpf/*/_cprog.
#
# clang compiles with -target bpf{el,eb}, so the host and image architecture do
# not affect the emitted bytecode -- only the clang version does. That version is
# therefore the reproducibility contract: `make verify-bpf` recompiles the
# committed C with this image and fails if the committed objects differ. Bump
# BPF_CLANG deliberately and regenerate every object in the same commit.
#
# The Go toolchain is required because bpf2go is a `tool` directive in go.mod and
# the //go:generate lines invoke `go tool bpf2go`.
FROM golang:1.26-trixie

ARG BPF_CLANG=19

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        "clang-${BPF_CLANG}" \
        "llvm-${BPF_CLANG}" \
        libbpf-dev \
        bpftool \
    && ln -sf "/usr/bin/clang-${BPF_CLANG}" /usr/local/bin/clang \
    && ln -sf "/usr/bin/llvm-strip-${BPF_CLANG}" /usr/local/bin/llvm-strip \
    && rm -rf /var/lib/apt/lists/*

# probe.c includes <linux/bpf.h>, which pulls <asm/types.h>. Debian installs the
# uapi asm headers under the multiarch triplet, and clang -target bpf does not
# search it. The types this reaches are fixed-width uapi scalars, so any triplet
# serves; symlink the native one to the search root.
RUN ARCH_INCLUDE="$(dirname "$(find /usr/include -maxdepth 2 -type d -name asm | head -n1)")" \
    && ln -sfn "${ARCH_INCLUDE}/asm" /usr/include/asm

RUN clang --version && llvm-strip --version && bpftool version
