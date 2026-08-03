package monitor

import (
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
)

// valueCorpus mixes every shape a policy can put in an open or exec values
// list, including the ones neither layer can honor.
var valueCorpus = []string{
	"/bin/sh",
	"/usr/bin/curl",
	" /usr/bin/wget\n",
	"/bin/sh",
	"/opt/my app/run",
	"/usr/bin/*",
	"kubectl",
	compiler.StarTarget,
	" * \n",
	"",
	"   ",
	"/bin/sh\x00/etc",
	"/" + strings.Repeat("a", compiler.MaxPathValueLen),
	strings.Repeat("/deep", 200),
}

// observedCorpus is what the kernel can hand back: paths bpf_d_path resolved,
// plus the near-misses that make exactness worth asserting.
var observedCorpus = []string{
	"/bin/sh",
	"/bin/shx",
	"/bin/s",
	" /bin/sh",
	"/usr/bin/curl",
	"/usr/bin/wget",
	"/usr/bin/wget2",
	"/opt/my app/run",
	"/usr/bin/*",
	"/usr/bin/anything",
	"kubectl",
	"/" + strings.Repeat("a", compiler.MaxPathValueLen),
	"",
	compiler.StarTarget,
}

// TestMonitorMatchesWhatTheKernelWouldMatch is the "monitor never lies" pin: for
// every value the corpus can hold, the userspace matcher's verdict equals a
// lookup against the keys lsm.AddTargets would program. A second tokenizer or a
// second length bound on either side breaks it.
func TestMonitorMatchesWhatTheKernelWouldMatch(t *testing.T) {
	m := newPathMatcher(valueCorpus)

	keys, star, rejected := lsm.ParsePaths(valueCorpus)
	if len(rejected) == 0 {
		t.Fatal("the corpus no longer contains a value the kernel maps reject")
	}
	programmed := make(map[lsm.PathKey]struct{}, len(keys))
	for _, k := range keys {
		programmed[k] = struct{}{}
	}

	if m.star != star {
		t.Errorf("matcher star = %v, kernel default deny = %v", m.star, star)
	}
	if len(m.paths) != len(programmed) {
		t.Errorf("matcher holds %d paths, the kernel maps hold %d keys", len(m.paths), len(programmed))
	}

	for _, path := range observedCorpus {
		key := lsm.PathKey{}
		copy(key[:], path)
		_, wantMatch := programmed[key]
		// the kernel never observes an empty path, and an all-NUL key is not a
		// path the maps can hold
		if path == "" {
			wantMatch = false
		}
		if got := m.matches(path); got != wantMatch {
			t.Errorf("matches(%q) = %v, kernel lookup = %v", path, got, wantMatch)
		}
	}
}

// TestRejectedValuesLeaveTheRestEnforceable pins the blast radius of one bad
// value: it is dropped by both layers, and every sibling value in the same list
// stays programmed and stays matched. A rejection that fails the whole list
// would leave a policy enforcing nothing while still reporting findings.
func TestRejectedValuesLeaveTheRestEnforceable(t *testing.T) {
	values := []string{"/bin/sh", strings.Repeat("/deep", 200), "/usr/bin/curl"}

	m := newPathMatcher(values)
	keys, _, rejected := lsm.ParsePaths(values)

	if len(keys) != 2 || len(rejected) != 1 {
		t.Fatalf("ParsePaths kept %d keys and rejected %d values, want 2 and 1", len(keys), len(rejected))
	}
	for _, path := range []string{"/bin/sh", "/usr/bin/curl"} {
		if !m.matches(path) {
			t.Errorf("matches(%q) = false, want true: a rejected sibling value must not disable the rest", path)
		}
	}
	if m.matches(strings.Repeat("/deep", 200)) {
		t.Error("the matcher matched a value the kernel maps cannot hold")
	}
}
