package lsm

import (
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"github.com/google/go-cmp/cmp"
)

func key(path string) PathKey {
	k := PathKey{}
	copy(k[:], path)
	return k
}

// TestPathKeyHoldsEveryValueTheGrammarAccepts pins the parser's length bound to
// the kernel key: bpf_probe_read_kernel_str always leaves a NUL terminator, so
// the longest usable path is one byte shorter than the key.
func TestPathKeyHoldsEveryValueTheGrammarAccepts(t *testing.T) {
	if compiler.MaxExecPathLen != maxPathLen-1 {
		t.Errorf("compiler.MaxExecPathLen = %d, want %d (char[%d] key minus its NUL terminator)",
			compiler.MaxExecPathLen, maxPathLen-1, maxPathLen)
	}
}

func TestParsePaths(t *testing.T) {
	tooLong := "/" + strings.Repeat("a", compiler.MaxExecPathLen)
	tests := []struct {
		name         string
		values       []string
		wantKeys     []PathKey
		wantStar     bool
		wantRejected []RejectedTarget
	}{
		{
			name:     "literal paths become keys in order",
			values:   []string{"/bin/sh", "/usr/bin/curl"},
			wantKeys: []PathKey{key("/bin/sh"), key("/usr/bin/curl")},
		},
		{
			name:     "star is the default deny sentinel, not a key",
			values:   []string{"*", "/bin/sh"},
			wantKeys: []PathKey{key("/bin/sh")},
			wantStar: true,
		},
		{
			name:     "surrounding whitespace is trimmed before keying",
			values:   []string{" /bin/sh\n"},
			wantKeys: []PathKey{key("/bin/sh")},
		},
		{
			name:     "duplicates collapse to one key",
			values:   []string{"/bin/sh", "/bin/sh ", "/bin/sh"},
			wantKeys: []PathKey{key("/bin/sh")},
		},
		{
			name:         "over-length value is rejected, not truncated",
			values:       []string{"/bin/sh", tooLong},
			wantKeys:     []PathKey{key("/bin/sh")},
			wantRejected: []RejectedTarget{{Value: tooLong, Reason: ReasonPathTooLong}},
		},
		{
			name:         "empty value is rejected",
			values:       []string{" ", ""},
			wantRejected: []RejectedTarget{{Value: " ", Reason: ReasonEmptyPath}, {Value: "", Reason: ReasonEmptyPath}},
		},
		{
			name:         "NUL-bearing value is rejected",
			values:       []string{"/bin/sh\x00/etc"},
			wantRejected: []RejectedTarget{{Value: "/bin/sh\x00/etc", Reason: ReasonNULInPath}},
		},
		{
			name:   "no values",
			values: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, star, rejected := ParsePaths(tt.values)
			if diff := cmp.Diff(tt.wantKeys, keys); diff != "" {
				t.Errorf("keys mismatch (-want +got):\n%s", diff)
			}
			if star != tt.wantStar {
				t.Errorf("star = %v, want %v", star, tt.wantStar)
			}
			if diff := cmp.Diff(tt.wantRejected, rejected); diff != "" {
				t.Errorf("rejected mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestAddAndDeleteTargetsKeyTheSameValues pins the invariant that keeps stale
// entries out of the kernel maps: every value AddTargets can program is a value
// DeleteTargets can remove, and both reject exactly the same ones. A length
// bound or a skip on either side alone leaks an entry nothing can delete.
func TestAddAndDeleteTargetsKeyTheSameValues(t *testing.T) {
	pair := &compiler.AllowDenyPair{
		Allow: []string{"/usr/bin/python3", "", "*", "/" + strings.Repeat("a", compiler.MaxExecPathLen)},
		Deny:  []string{"/bin/sh", "/bin/sh\x00", " /usr/bin/curl ", "*"},
	}

	addDeny, addAllow, addRejected := parsePair(pair)
	delDeny, delAllow, delRejected := parsePair(pair)

	if diff := cmp.Diff(addDeny, delDeny); diff != "" {
		t.Errorf("deny keys differ between add and delete (-add +delete):\n%s", diff)
	}
	if diff := cmp.Diff(addAllow, delAllow); diff != "" {
		t.Errorf("allow keys differ between add and delete (-add +delete):\n%s", diff)
	}
	if diff := cmp.Diff(addRejected, delRejected); diff != "" {
		t.Errorf("rejections differ between add and delete (-add +delete):\n%s", diff)
	}

	wantDeny := []PathKey{key("/bin/sh"), key("/usr/bin/curl")}
	if diff := cmp.Diff(wantDeny, addDeny); diff != "" {
		t.Errorf("deny keys mismatch (-want +got):\n%s", diff)
	}
	wantAllow := []PathKey{key("/usr/bin/python3")}
	if diff := cmp.Diff(wantAllow, addAllow); diff != "" {
		t.Errorf("allow keys mismatch (-want +got):\n%s", diff)
	}
	if len(addRejected) != 3 {
		t.Errorf("rejected = %v, want the empty, NUL-bearing and over-length values", addRejected)
	}
}

func TestParsePairOnNilPair(t *testing.T) {
	deny, allow, rejected := parsePair(nil)
	if deny != nil || allow != nil || rejected != nil {
		t.Errorf("parsePair(nil) = %v, %v, %v, want all nil", deny, allow, rejected)
	}
}

func TestRejectedTargetNamesValueAndReason(t *testing.T) {
	got := RejectedTarget{Value: "/bin/sh", Reason: ReasonPathTooLong}.String()
	if !strings.Contains(got, "/bin/sh") || !strings.Contains(got, ReasonPathTooLong) {
		t.Errorf("String() = %q, want it to name both the value and the reason", got)
	}
}
