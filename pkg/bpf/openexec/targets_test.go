package openexec

import (
	"strings"
	"testing"

	"github.com/nirmata/runtime/pkg/compiler"

	"github.com/google/go-cmp/cmp"
)

func allowEntry(path string) *runtimePolicyEntry { return entryFor(path, 0) }
func denyEntry(path string) *runtimePolicyEntry  { return entryFor(path, 1) }

func entryFor(path string, dataType uint32) *runtimePolicyEntry {
	e := &runtimePolicyEntry{DataType: dataType}
	for i := 0; i < len(path) && i < len(e.Data); i++ {
		e.Data[i] = int8(path[i])
	}
	return e
}

var cmpEntries = cmp.AllowUnexported(runtimePolicyEntry{})

// TestPathKeyHoldsEveryValueTheSchemaAccepts pins the parser's length bound to
// the kernel key: bpf_probe_read_kernel_str always leaves a NUL terminator, so
// the longest usable path is one byte shorter than the key.
func TestPathKeyHoldsEveryValueTheSchemaAccepts(t *testing.T) {
	if compiler.MaxPathValueLen != maxPathLen-1 {
		t.Errorf("compiler.MaxPathValueLen = %d, want %d (char[%d] key minus its NUL terminator)",
			compiler.MaxPathValueLen, maxPathLen-1, maxPathLen)
	}
}

func TestPathKeys(t *testing.T) {
	tooLong := "/" + strings.Repeat("a", compiler.MaxPathValueLen)
	tests := []struct {
		name         string
		values       []string
		allow        bool
		wantKeys     []*runtimePolicyEntry
		wantStar     bool
		wantRejected []compiler.RejectedTarget
	}{
		{
			name:     "literal allow paths become allow entries in order",
			values:   []string{"/bin/sh", "/usr/bin/curl"},
			allow:    true,
			wantKeys: []*runtimePolicyEntry{allowEntry("/bin/sh"), allowEntry("/usr/bin/curl")},
		},
		{
			name:     "literal deny paths become deny entries",
			values:   []string{"/bin/sh"},
			allow:    false,
			wantKeys: []*runtimePolicyEntry{denyEntry("/bin/sh")},
		},
		{
			name:     "star is the default deny sentinel, not a key",
			values:   []string{"*", "/bin/sh"},
			allow:    true,
			wantKeys: []*runtimePolicyEntry{allowEntry("/bin/sh")},
			wantStar: true,
		},
		{
			name:     "surrounding whitespace is trimmed before keying",
			values:   []string{" /bin/sh\n"},
			allow:    true,
			wantKeys: []*runtimePolicyEntry{allowEntry("/bin/sh")},
		},
		{
			name:     "duplicates collapse to one key",
			values:   []string{"/bin/sh", "/bin/sh ", "/bin/sh"},
			allow:    true,
			wantKeys: []*runtimePolicyEntry{allowEntry("/bin/sh")},
		},
		{
			name:         "over-length value is rejected, not truncated",
			values:       []string{"/bin/sh", tooLong},
			allow:        true,
			wantKeys:     []*runtimePolicyEntry{allowEntry("/bin/sh")},
			wantRejected: []compiler.RejectedTarget{{Value: tooLong, Reason: compiler.ErrPathValueTooLong.Error()}},
		},
		{
			name:   "empty value is rejected",
			values: []string{" ", ""},
			allow:  true,
			wantRejected: []compiler.RejectedTarget{
				{Value: " ", Reason: compiler.ErrEmptyPathValue.Error()},
				{Value: "", Reason: compiler.ErrEmptyPathValue.Error()},
			},
		},
		{
			name:         "NUL-bearing value is rejected",
			values:       []string{"/bin/sh\x00/etc"},
			allow:        true,
			wantRejected: []compiler.RejectedTarget{{Value: "/bin/sh\x00/etc", Reason: compiler.ErrNULInPathValue.Error()}},
		},
		{
			name:   "no values",
			values: nil,
			allow:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, star, rejected := PathKeys(tt.values, tt.allow)
			if diff := cmp.Diff(tt.wantKeys, keys, cmpEntries); diff != "" {
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
		Allow: []string{"/usr/bin/python3", "", "*", "/" + strings.Repeat("a", compiler.MaxPathValueLen)},
		Deny:  []string{"/bin/sh", "/bin/sh\x00", " /usr/bin/curl ", "*"},
	}

	addDeny, addAllow, addRejected := parsePair(pair)
	delDeny, delAllow, delRejected := parsePair(pair)

	if diff := cmp.Diff(addDeny, delDeny, cmpEntries); diff != "" {
		t.Errorf("deny keys differ between add and delete (-add +delete):\n%s", diff)
	}
	if diff := cmp.Diff(addAllow, delAllow, cmpEntries); diff != "" {
		t.Errorf("allow keys differ between add and delete (-add +delete):\n%s", diff)
	}
	if diff := cmp.Diff(addRejected, delRejected); diff != "" {
		t.Errorf("rejections differ between add and delete (-add +delete):\n%s", diff)
	}

	wantDeny := []*runtimePolicyEntry{denyEntry("/bin/sh"), denyEntry("/usr/bin/curl")}
	if diff := cmp.Diff(wantDeny, addDeny, cmpEntries); diff != "" {
		t.Errorf("deny keys mismatch (-want +got):\n%s", diff)
	}
	wantAllow := []*runtimePolicyEntry{allowEntry("/usr/bin/python3")}
	if diff := cmp.Diff(wantAllow, addAllow, cmpEntries); diff != "" {
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
