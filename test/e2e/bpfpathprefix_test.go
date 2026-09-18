package e2e_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nirmata/runtime/pkg/bpf/openexec"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/utils"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"
)

// TestBPFDirectoryPrefixDeniesInKernel opens real files through the hook the
// host actually supports — BPF-LSM where it is booted, fmod_ret otherwise, the
// same choice NewOpenExecManager makes — so the two CI lanes between them prove
// the directory form on both. Attaching and programming maps is not the
// assertion here; the return value of open(2) is.
func TestBPFDirectoryPrefixDeniesInKernel(t *testing.T) {
	requireBPFCapableHost(t)

	lsm, err := utils.BpfLSMEnabled()
	if err != nil {
		t.Skipf("cannot determine active LSMs: %v", err)
	}
	target := openexec.PROG_TYPE_TRACE_OPEN
	if lsm {
		target = openexec.PROG_TYPE_LSM_OPEN
	}

	if err := openexec.ClearPins(); err != nil {
		t.Fatalf("clearing pins: %v", err)
	}

	dir := t.TempDir()
	blocked := filepath.Join(dir, "lib")
	nested := filepath.Join(blocked, "x86_64", "deep")
	sibling := filepath.Join(dir, "library")
	for _, d := range []string{nested, sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	denied := filepath.Join(blocked, "libc.so")
	deniedDeep := filepath.Join(nested, "libm.so")
	allowed := filepath.Join(sibling, "libc.so")
	itself := blocked
	for _, f := range []string{denied, deniedDeep, allowed} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	logger := logr.Discard()
	d, err := openexec.NewDispatcherForTarget(target)
	if err != nil {
		t.Fatalf("loading dispatcher for %q: %+v", target, err)
	}
	if err := d.Attach(); err != nil {
		t.Fatalf("attaching %q: %+v", target, err)
	}
	if _, err := openexec.NewProgram(d); err != nil {
		t.Fatalf("loading the policy executor for %q: %+v", target, err)
	}

	enf, err := openexec.NewPolicyMap(d, &logger)
	if err != nil {
		t.Fatalf("creating a policy map for %q: %+v", target, err)
	}
	t.Cleanup(func() {
		if err := enf.Close(); err != nil {
			t.Errorf("closing the policy map: %v", err)
		}
	})

	// an allow of a file inside the denied directory, to pin that a deny is not
	// something an allow can carve an exception out of
	pair := &compiler.AllowDenyPair{
		Deny:  []string{blocked + "/*"},
		Allow: []string{denied},
	}
	rejected, err := enf.AddTargets(pair)
	if err != nil {
		t.Fatalf("programming targets: %v", err)
	}
	if len(rejected) != 0 {
		t.Fatalf("programming targets rejected %v", rejected)
	}

	cgid := selfCgroupID(t)
	if err := enf.AddCgids([]uint64{cgid}); err != nil {
		t.Fatalf("attaching cgroup %d: %v", cgid, err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "file directly under the directory", path: denied, wantErr: true},
		{name: "file below it at depth", path: deniedDeep, wantErr: true},
		{name: "directory with the same leading bytes", path: allowed},
		{name: "the directory itself is not under itself", path: itself},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := openFor(tt.path)
			switch {
			case tt.wantErr && !errors.Is(err, unix.EPERM):
				t.Errorf("open(%q) = %v, want EPERM", tt.path, err)
			case !tt.wantErr && err != nil:
				t.Errorf("open(%q) = %v, want success", tt.path, err)
			}
		})
	}

	// a second policy on the same cgroup: its allow cannot lift the first
	// policy's directory deny, and its default deny is lifted by the first
	// policy's allow of a path under the sibling directory
	other, err := openexec.NewPolicyMap(d, &logger)
	if err != nil {
		t.Fatalf("creating a second policy map for %q: %+v", target, err)
	}
	t.Cleanup(func() {
		if err := other.Close(); err != nil {
			t.Errorf("closing the second policy map: %v", err)
		}
	})
	if _, err := other.AddTargets(&compiler.AllowDenyPair{Allow: []string{denied}}); err != nil {
		t.Fatalf("programming the second policy's targets: %v", err)
	}
	if err := other.SetDefaultDeny(true); err != nil {
		t.Fatalf("setting the second policy's default deny: %v", err)
	}
	if _, err := enf.AddTargets(&compiler.AllowDenyPair{Allow: []string{allowed}}); err != nil {
		t.Fatalf("programming the first policy's allow: %v", err)
	}
	if err := other.AddCgids([]uint64{cgid}); err != nil {
		t.Fatalf("attaching cgroup %d to the second policy: %v", cgid, err)
	}

	t.Run("another policy's allow does not lift a directory deny", func(t *testing.T) {
		if err := openFor(denied); !errors.Is(err, unix.EPERM) {
			t.Errorf("open(%q) = %v, want EPERM", denied, err)
		}
	})
	t.Run("another policy's allow lifts a default deny", func(t *testing.T) {
		if err := openFor(allowed); err != nil {
			t.Errorf("open(%q) = %v, want success", allowed, err)
		}
	})
	t.Run("default deny bites a path no policy allows", func(t *testing.T) {
		if err := openFor(deniedDeep); !errors.Is(err, unix.EPERM) {
			t.Errorf("open(%q) = %v, want EPERM", deniedDeep, err)
		}
	})

	if err := other.Close(); err != nil {
		t.Fatalf("closing the second policy map: %v", err)
	}
	if _, err := enf.DeleteTargets(pair); err != nil {
		t.Fatalf("removing targets: %v", err)
	}
	if err := openFor(denied); err != nil {
		t.Errorf("open(%q) after the policy was removed = %v, want success", denied, err)
	}
}

func openFor(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return f.Close()
}
