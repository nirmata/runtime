package openexec

import (
	"errors"
	"os"
	"testing"

	"github.com/nirmata/runtime/pkg/utils"

	"github.com/cilium/ebpf"
)

// TestGeneratedObjectsLoad loads the objects in the daemon's order — both
// dispatchers, then an enforcer per target — sharing one pin directory, so a
// prog-array ownership conflict fails here with the full verifier log instead
// of at policy-apply time.
func TestGeneratedObjectsLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}

	required := os.Getenv("NIRMATA_RUNTIME_REQUIRE_BPF_LSM") == "1"
	on, err := utils.BpfLSMEnabled()
	switch {
	case err != nil && required:
		t.Fatalf("NIRMATA_RUNTIME_REQUIRE_BPF_LSM=1 but whether BPF-LSM is available could not be determined: %v", err)
	case err != nil:
		t.Skipf("cannot determine whether BPF-LSM is available: %v", err)
	case !on && required:
		t.Fatal("NIRMATA_RUNTIME_REQUIRE_BPF_LSM=1 but BPF-LSM is unavailable: kernel not booted with BPF-LSM " +
			"('bpf' absent from /sys/kernel/security/lsm); boot it with lsm=...,bpf")
	case !on:
		t.Skip("BPF-LSM unavailable: kernel not booted with BPF-LSM ('bpf' absent from /sys/kernel/security/lsm); " +
			"boot it with lsm=...,bpf")
	}

	pin := "/sys/fs/bpf/loadcheck"
	if err := os.MkdirAll(pin, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(pin) })
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pin}}

	fatal := func(t *testing.T, err error) {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("%+v", verr)
		}
		t.Fatal(err)
	}

	dispSpec, err := loadLsmDispatcherFileOpen()
	if err != nil {
		t.Fatal(err)
	}
	dispSpec.Programs["generic_lsm_handler"].AttachTo = PROG_TYPE_LSM_OPEN
	dispSpec.Programs["generic_lsm_handler"].AttachType = ebpf.AttachLSMMac
	dispObjs := &lsmDispatcherFileOpenObjects{}
	if err := dispSpec.LoadAndAssign(dispObjs, opts); err != nil {
		fatal(t, err)
	}
	defer dispObjs.Close()

	execSpec, err := loadLsmDispatcherExecCheck()
	if err != nil {
		t.Fatal(err)
	}
	execSpec.Programs["generic_lsm_handler"].AttachTo = PROG_TYPE_LSM_EXEC
	execSpec.Programs["generic_lsm_handler"].AttachType = ebpf.AttachLSMMac
	execObjs := &lsmDispatcherExecCheckObjects{}
	if err := execSpec.LoadAndAssign(execObjs, opts); err != nil {
		fatal(t, err)
	}
	defer execObjs.Close()

	enforcers := []struct {
		target string
		array  *ebpf.Map
	}{
		{PROG_TYPE_LSM_OPEN, dispObjs.OpenProgs},
		{PROG_TYPE_LSM_EXEC, execObjs.ExecProgs},
	}
	for _, e := range enforcers {
		t.Run("enforcer_"+e.target, func(t *testing.T) {
			spec, err := loadLsmRuntimePolicy()
			if err != nil {
				t.Fatal(err)
			}
			spec.Programs["runtime_policy_executor"].AttachTo = e.target
			spec.Programs["runtime_policy_executor"].AttachType = ebpf.AttachLSMMac
			prepareOpenEvents(spec)
			objs := &lsmRuntimePolicyObjects{}
			eopts := *opts
			eopts.MapReplacements = map[string]*ebpf.Map{"chain_progs": e.array}
			if err := spec.LoadAndAssign(objs, &eopts); err != nil {
				fatal(t, err)
			}
			objs.Close()
		})
	}
}
