package lsm

import (
	"strings"
	"testing"

	"github.com/go-logr/logr"
)

// The known targets require a kernel with BPF-LSM, so only the switch default
// is host independent. Attach target strings come from the manager, so an
// unknown one must be reported rather than silently producing a nil enforcer.
func TestNewForAttachTargetUnknownTarget(t *testing.T) {
	discard := logr.Discard()

	for _, target := range []string{"", "bogus", "socket_connect", "FILE_OPEN"} {
		t.Run(target, func(t *testing.T) {
			enf, err := NewForAttachTarget(&discard, target)
			if err == nil {
				t.Fatalf("NewForAttachTarget(%q) succeeded, want an error", target)
			}
			if enf != nil {
				t.Errorf("NewForAttachTarget(%q) returned a non nil enforcer alongside the error", target)
			}
			if !strings.Contains(err.Error(), "unknown lsm attach target") {
				t.Errorf("error = %q, want it to mention the unknown attach target", err)
			}
			if !strings.Contains(err.Error(), target) {
				t.Errorf("error = %q, want it to include the offending target %q", err, target)
			}
		})
	}
}
