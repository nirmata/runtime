# Working on kyverno-runtime

Conventions for anyone — human or agent — changing this repo. `Agents.md` covers
task workflow and the package map; `DEVELOPMENT.md` covers build and test
mechanics. This file is about the judgment that review keeps catching.

Every rule below is here because it was violated in a real PR and a reviewer had
to spend time on it.

## Ship nothing without a producer

Do not land a type, field, struct member, metric, enum value, mode, or interface
method that nothing in production writes. "The next PR needs it" and "so that PR
adds no new files" are not reasons. They are how a package accumulates surface
that readers must reason about and nobody can exercise.

The tell is a grep: if the only non-test reference to an identifier is its own
declaration, it does not belong in the commit.

This applies to whole subsystems. A redaction chokepoint for a protocol no
source emits is not a security control; it is untested code that looks like one.

## Keep each PR self-contained

No comment, doc, or identifier may reference unmerged work. No "PR A", no
"filled in by PR B", no "added by the AI detection work". A reader six months
from now has the merged tree and git history, not your branch plan.

If a change only makes sense as part of a sequence, the commit message is where
that context goes — not the code.

## Comments describe the code as it stands

What it does and why, never where it came from or what will happen to it.

- **No issue or PR numbers.** `(#41)`, `see issue #60`, `the #52 bug class` — the
  tracker holds that, and git blame holds the rest. Keep the explanation, drop
  the reference: "an early break made the counts of every enforcer after the
  first invisible" is useful forever; "#52" stops being useful the moment the
  tracker moves.
- **No issue numbers in identifiers either.** Not `TestFooBar_Issue59`. Name the
  invariant: `TestPodRequeueCapSurvivesPointerChange`. The invariant outlives the
  ticket.
- **A comment must carry more than the signature below it.** Three lines
  explaining why a struct has a `Name` field is noise.
- **A comment block longer than the body it explains is a smell.** Seven lines
  of narration above a one-line `return nil, fmt.Errorf(...)` means the
  narration is doing something other than explaining the code.
- **Do not let a comment go stale into a lie.** One said `V(0):` above a plain
  `.Info()` call; another documented an observation limit that a later commit in
  the same PR had removed. If you change behavior, grep for comments describing
  the old behavior.

Keep facts that are genuinely non-obvious from the signature. That
`buildCandidatePaths` takes a **raw** pod UID and escapes it internally is a
trap worth documenting; the fact that it builds paths is not.

## One grammar, one home

If two packages parse the same user-facing value, they will diverge. In this
repo three did: the egress filter trimmed `\r\n` from policy targets and the
admission validator did not, so `"1.2.3.4\n"` was programmed into the BPF maps
but rejected at admission — inverting the invariant that admission must never
reject what the runtime accepts.

Parse in exactly one function. When two layers need different strictness, that is
one permissive grammar plus one explicit, documented narrowing point — not two
grammars that agree by coincidence and a comment claiming they agree.

## A no-op method means you have two interfaces

If a type implements an interface method as `return nil` purely to satisfy the
signature, the interface is over-broad. Split it. The compiler then enforces who
listens to what, and the stubs stop existing rather than being maintained.

The same logic applies to parameters. If every implementation ignores an
argument on a given path, remove it from that path — a `*corev1.Pod` whose only
read field is `UID` should be a UID, and a slice nobody reads should not be
stashed on one path to be passed on another.

## Observability has to be decision-aware

A counter that cannot distinguish an allowed operation from a blocked one is not
monitoring, however many events it produces. Put each dimension in the layer
that actually knows it:

- The **kernel** knows the verdict and has no policy identity. Encode the verdict
  in the map key.
- **Userspace** knows the policies. Attribute there, by re-evaluating the
  compiled policy against the observed target.

And structure the hot path so observation cannot be skipped: compute the
decision, record it, then act on it. This repo shipped an observation branch
sitting after an enforcement `return`, which meant every pod with a default-deny
policy observed nothing at all — the exact traffic an operator most wants to see.

When an event cannot be attributed, count it and log it. Never drop it silently:
a monitoring gap that looks identical to "nothing happened" is worse than an
error.

## Generated artifacts need a path back to their source

Committed binaries — BPF objects, CRDs, clients — must be reproducible by a
pinned toolchain from committed source, and CI must check it. Nobody reviews
bytecode; the drift check is what makes a binary diff trustworthy.

If generation needs a tool the developer hosts lack, containerize it (see
`hack/bpf-builder/`) rather than recompiling by hand. And if generation depends
on an input, that input must be committed too — a gitignored `vmlinux.h` makes
the build unreproducible by construction. Prefer a small hand-maintained input
you can review over a large generated one you cannot.

## In code review, check claims before acting on them

Reviewers are usually right, and when they are, fix it and say so plainly. But
verify: in one review, "cel.go is already panic safe" named a file that does not
exist in this repo, and "the previous code already called handlers in separate
goroutines" described a refactor as if it had introduced the concurrency it
actually de-duplicated.

Both were settled in one grep. Reply with the evidence — the quoted code, the
old diff — not with an opinion. And when a reviewer is right about something
larger than they realized, say that too: "you asked whether denies are invisible
under default deny; it is worse than that, nothing is observed at all" is a
better answer than a fix with no explanation.

## Delete on sight

Empty structs. Exported functions with no callers. Compile-time interface
assertions duplicating a typed wiring site three lines below. Commented-out
declarations. These cost nothing to remove and compound if left.
