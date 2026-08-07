# Working on kyverno-runtime

Conventions for anyone — human or agent — changing this repo. `Agents.md` covers
task workflow and the package map; `docs/dev/DEVELOPMENT.md` covers build and test
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

## Comments earn their place or they go

The default is no comment. Write one only where a competent reader of the code
would still get it wrong. Everything else is cost: it has to be read, and it
has to be kept true.

- **Never write historical context.** Not "no longer", not "used to", not
  "previously", not "preserved byte-for-byte". A diff that says what the code
  did before is describing something the reader cannot see and does not need.
  Git holds it. A reviewer's exact words on the third instance of this in one
  PR: *"please NEVER do that"*.
- **No issue or PR numbers**, in comments or in identifiers. Not `(#41)`, not
  `TestFooBar_Issue59`. Name the invariant instead:
  `TestPodRequeueCapSurvivesPointerChange` — it outlives the ticket.
- **A comment must carry more than the signature below it.** Three lines on why
  a struct has a `Name` field is noise. So is a comment above
  `if verdict == DENY { return 0 }`.
- **No package doc comments** in this repo.
- **A comment block longer than the body it explains is a smell.** Seven lines
  of narration above a one-line `return nil, fmt.Errorf(...)` is doing
  something other than explaining the code.
- **No error-handling narration.** "If this fails we log and continue" is
  visible in the three lines underneath it.
- **No loud notation.** ALL-CAPS MUST/NEVER/ALWAYS and em-dash flourishes
  arguing with an imagined objector are not documentation.
- **Never name a log level in a comment.** "surfaced at V(0)" and "logged at
  V(2)" are true until someone retunes verbosity, and nothing fails when they
  stop being true. Say where the value reaches an operator — logs, a status
  condition — not at what level.
- **Do not let a comment go stale into a lie.** One said `V(0):` above a plain
  `.Info()` call; another documented an observation limit a later commit in the
  same PR had removed. Change behavior, then grep for comments describing the
  old behavior.
- **BPF C files stay near-bare.** Document a kernel program's design in the Go
  layer that loads it, or in the project docs — not in the `.bpf.c`. A C
  comment is for the single line a reader would otherwise misread.

The failure mode is not "too many comments" on its own — it is spending the
reader's attention in the wrong place. The same review that cut thirty blocky
comments also asked for four new ones, all on genuinely clever code:
*"crazy how you overexplained many parts of the codebase and left no proper
explanation in the part where we actually need it."* A goroutine-per-source
fan-in, a non-blocking handoff, a padding-free BPF map key, a poller that wraps
a single manager: one line each, because none of them are readable from the
signature. `buildCandidatePaths` taking a **raw** pod UID and escaping it
internally is the same kind of trap. That it builds paths is not.

## A panic is a bug report, not a runtime condition

Do not wrap library or internal calls in a recover() barrier on the theory that
anything might panic. If a dependency we rely on panics, or an index is out of
range, we have a bug and the process should die loudly where it broke — not
convert it into an error that gets logged and swallowed three layers up.

- **Programmer errors panic.** An out-of-range flag index, a constructor handed
  a nil collector func: panic. Do not return an error the caller cannot act on.
- **`utils.Guard` is for fan-out boundaries only** — the collector's stages and
  sinks, and the informer handler fan-out — where one misbehaving handler must
  not take out the other handlers on the same event. Not for CEL compile, not
  for CEL eval: cel-go recovers inside its own interpreter and returns an
  error, which is exactly the contract we want.
- **User input is validated, not guarded.** A malformed policy must be rejected
  by admission or produce a status condition. Reaching for `recover()` to make
  bad input survivable means the validation is in the wrong place.

The reviewer's framing, which is the right one: *"if it panics then this means
we messed up pretty badly and i don't think this should be silenced."*

## One schema, one home

If two packages parse the same user-facing value, they will diverge. In this
repo three did: the egress filter trimmed `\r\n` from policy targets and the
admission validator did not, so `"1.2.3.4\n"` was programmed into the BPF maps
but rejected at admission — inverting the invariant that admission must never
reject what the runtime accepts.

Parse in exactly one function. When two layers need different strictness, that is
one permissive schema plus one explicit, documented narrowing point — not two
schemas that agree by coincidence and a comment claiming they agree.

Chokepoint the *list*, not just the value. Sharing `ParsePathValue` was not
enough: the enforcer and the monitor each kept their own loop around it, each
with its own dedupe and its own idea of what to do with a value that failed —
which is a second schema wearing the first one's clothes. `ParsePathList`
returns the accepted values, the sentinel, and the rejects, and both callers
take all three.

Say **schema**, not "grammar" — reviewer's words: *"no one says this in normal
conversation."*

A rejection reason is part of the schema and lives with it. Do not define a
parallel vocabulary of reason strings in the consuming package and a `switch`
to translate errors into it: put the remedy in the sentinel error, and let
callers surface `err.Error()`.

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

- The **kernel** knows the decision and has no policy identity. Encode the decision
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

## Zero what the kernel hands to userspace

A reserved ring buffer record arrives holding whatever the last event on that
CPU wrote, and every byte of it is mmapped to userspace. Fill every field or
zero the record first: an unzeroed tail leaks one pod's argv into another
pod's event, which is a confidentiality bug, not untidiness.

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

## Names and shapes

A reader infers behavior from a name and a signature before reading a body.
Both have to be honest, and neither should hide the thing the reader came for.

- **Name a function for its job, not for a step inside it.** `ParsePaths` reads
  as a syntax check on a list of paths; what it actually returns is the kernel
  map keys, so it is `PathKeys`. The reviewer's test: say out loud what the
  caller wanted, and see whether the name is that.
- **One concept, one type.** `RejectedTarget` was declared identically in
  `pkg/bpf/lsm` and `pkg/bpf/egressfilter`, so the same struct needed two
  imports, two `String()` methods and two sets of tests. If two packages
  produce the same shape, it belongs in the package they both already import.
- **A type alias over a fixed-size array hides the shape.** `type PathKey =
  [maxPathLen]byte` reads fine at the declaration and tells a caller nothing:
  `[][maxPathLen]byte` at the call site says how wide the key is, which is the
  one fact a reader of BPF map code needs. Spell the array.
- **Do not build layers to reach a one-line call.** Two wrapper functions and a
  nested closure around `ParsePathValue` is not abstraction; the parameter that
  varies is a `func(string) error`, so pass it and stop.

## Delete on sight

Empty structs. Exported functions with no callers. Compile-time interface
assertions duplicating a typed wiring site three lines below. Commented-out
declarations. These cost nothing to remove and compound if left.
