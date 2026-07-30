# Builder image for BPF ELF generation from pkg/bpf/*/_cprog. The pinned clang
# version is the reproducibility contract: `make verify-bpf` recompiles with
# this image and fails if the committed objects differ. Go is needed because
# bpf2go is a `tool` directive in go.mod.
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

# Debian installs the uapi asm headers under the multiarch triplet, which
# clang -target bpf does not search. Symlink the native one to the search root.
RUN ARCH_INCLUDE="$(dirname "$(find /usr/include -maxdepth 2 -type d -name asm | head -n1)")" \
    && ln -sfn "${ARCH_INCLUDE}/asm" /usr/include/asm

RUN clang --version && llvm-strip --version && bpftool version
