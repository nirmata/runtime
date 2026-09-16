package monitor

import (
	"strings"
	"testing"

	"github.com/nirmata/runtime/pkg/bpf/openexec"
	"github.com/nirmata/runtime/pkg/compiler"
)

// valueCorpus mixes every shape a policy can put in an open or exec values
// list, including the ones neither layer can honor.
var valueCorpus = []string{
	"/bin/sh",
	"/usr/bin/curl",
	" /usr/bin/wget\n",
	"/bin/sh",
	"/opt/my app/run",
	"/usr/lib/*",
	"/usr/lib/**",
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
	"/usr/lib/libc.so",
	"/usr/lib/x86_64-linux-gnu/libc.so.6",
	"/usr/lib",
	"/usr/library/libc.so",
	"/usr/bin/anything",
	"kubectl",
	"/" + strings.Repeat("a", compiler.MaxPathValueLen),
	"",
	compiler.StarTarget,
}

// TestMonitorMatchesWhatTheKernelWouldMatch is the "monitor never lies" pin: for
// every value the corpus can hold, the userspace matcher's verdict equals a
// lookup against the keys openexec.AddTargets would program. A second tokenizer or a
// second length bound on either side breaks it.
func TestMonitorMatchesWhatTheKernelWouldMatch(t *testing.T) {
	m := newPathMatcher(valueCorpus)

	keys, star, rejected := openexec.PathKeys(valueCorpus, true)
	if len(rejected) == 0 {
		t.Fatal("the corpus no longer contains a value the kernel maps reject")
	}
	// a literal can never end in a separator, so the trailing one the schema
	// keeps on a directory tells the two kinds of key apart without reaching
	// for the kernel's discriminant
	programmed := make(map[string]struct{}, len(keys))
	prefixes := make(map[string]struct{})
	for _, k := range keys {
		key := trimEntry(k.Data)
		if strings.HasSuffix(key, "/") {
			prefixes[key] = struct{}{}
			continue
		}
		programmed[key] = struct{}{}
	}

	if m.star != star {
		t.Errorf("matcher star = %v, kernel default deny = %v", m.star, star)
	}
	if len(m.paths) != len(programmed) || len(m.prefixes) != len(prefixes) {
		t.Errorf("matcher holds %d paths and %d prefixes, the kernel maps hold %d and %d",
			len(m.paths), len(m.prefixes), len(programmed), len(prefixes))
	}

	for _, path := range observedCorpus {
		_, wantMatch := programmed[path]
		// the kernel walks the observed path's ancestors against the same
		// directory keys, bounded at the same depth
		for _, dir := range compiler.AncestorDirs(path) {
			if _, ok := prefixes[dir]; ok {
				wantMatch = true
			}
		}
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
	keys, _, rejected := openexec.PathKeys(values, true)

	if len(keys) != 2 || len(rejected) != 1 {
		t.Fatalf("PathKeys kept %d keys and rejected %d values, want 2 and 1", len(keys), len(rejected))
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

// trimEntry is the inverse of the NUL padding openexec.PathKeys applies; a path
// holds no NUL byte, so the first one always ends the string.
func trimEntry(data [compiler.MaxPathValueLen + 1]int8) string {
	out := make([]byte, 0, len(data))
	for _, b := range data {
		if b == 0 {
			break
		}
		out = append(out, byte(b))
	}
	return string(out)
}
