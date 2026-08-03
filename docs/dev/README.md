# Developer documentation

- [DEVELOPMENT.md](DEVELOPMENT.md) — prerequisites, build and test targets, the local kind
  workflow, generated artifacts, and CI.
- [DESIGN.md](DESIGN.md) — the current architecture: how policies are compiled, how the two
  eBPF programs are attached and drained, and the known gaps.
- [POSITIONING.md](POSITIONING.md) — what this project is for alongside an LLM/MCP gateway, a
  MITM TLS proxy, a CNI, and admission control, and what it deliberately cedes to each.

Conventions live at the repo root: [CLAUDE.md](../../CLAUDE.md) for the review rules that apply
to code, comments, and docs, and [Agents.md](../../Agents.md) for task workflow and the
one-line-per-package map.

User-facing documentation is under [docs/users/](../users/).
