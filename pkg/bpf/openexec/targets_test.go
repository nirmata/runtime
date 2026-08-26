package openexec

import (
	"strings"
	"testing"

	"github.com/nirmata/runtime/pkg/compiler"

	"github.com/google/go-cmp/cmp"
)

func key(path string) [maxPathLen]byte {
	k := [maxPathLen]byte{}
	copy(k[:], path)
	return k
}

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
		wantKeys     [][maxPathLen]byte
		wantStar     bool
		wantRejected []compiler.RejectedTarget
	}{
		{
			name:     "literal paths become keys in order",
			values:   []string{"/bin/sh", "/usr/bin/curl"},
			wantKeys: [][maxPathLen]byte{key("/bin/sh"), key("/usr/bin/curl")},
		},
		{
			name:     "star is the default deny sentinel, not a key",
			values:   []string{"*", "/bin/sh"},
			wantKeys: [][maxPathLen]byte{key("/bin/sh")},
			wantStar: true,
		},
		{
			name:     "surrounding whitespace is trimmed before keying",
			values:   []string{" /bin/sh\n"},
			wantKeys: [][maxPathLen]byte{key("/bin/sh")},
		},
		{
			name:     "duplicates collapse to one key",
			values:   []string{"/bin/sh", "/bin/sh ", "/bin/sh"},
			wantKeys: [][maxPathLen]byte{key("/bin/sh")},
		},
		{
			name:         "over-length value is rejected, not truncated",
			values:       []string{"/bin/sh", tooLong},
			wantKeys:     [][maxPathLen]byte{key("/bin/sh")},
			wantRejected: []compiler.RejectedTarget{{Value: tooLong, Reason: compiler.ErrPathValueTooLong.Error()}},
		},
		{
			name:   "empty value is rejected",
			values: []string{" ", ""},
			wantRejected: []compiler.RejectedTarget{
				{Value: " ", Reason: compiler.ErrEmptyPathValue.Error()},
				{Value: "", Reason: compiler.ErrEmptyPathValue.Error()},
			},
		},
		{
			name:         "NUL-bearing value is rejected",
			values:       []string{"/bin/sh\x00/etc"},
			wantRejected: []compiler.RejectedTarget{{Value: "/bin/sh\x00/etc", Reason: compiler.ErrNULInPathValue.Error()}},
		},
		{
			name:   "no values",
			values: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, star, rejected := PathKeys(tt.values)
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
		Allow: []string{"/usr/bin/python3", "", "*", "/" + strings.Repeat("a", compiler.MaxPathValueLen)},
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

	wantDeny := [][maxPathLen]byte{key("/bin/sh"), key("/usr/bin/curl")}
	if diff := cmp.Diff(wantDeny, addDeny); diff != "" {
		t.Errorf("deny keys mismatch (-want +got):\n%s", diff)
	}
	wantAllow := [][maxPathLen]byte{key("/usr/bin/python3")}
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
