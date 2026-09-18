package openexec

import (
	"os"
	"runtime"
	"testing"

	"github.com/nirmata/runtime/pkg/utils"
)

func TestExecutedWithoutProgramReportsTrue(t *testing.T) {
	d := &Dispatcher{dispatcherType: PROG_TYPE_TRACE_EXEC}
	called := false
	ran, err := d.Executed(func() error { called = true; return nil })
	if err != nil || !ran || called {
		t.Fatalf("ran=%t called=%t err=%v, want true without running the canary", ran, called, err)
	}
}

func TestCloseOnUnloadedDispatcherIsNil(t *testing.T) {
	d := &Dispatcher{dispatcherType: PROG_TYPE_LSM_OPEN}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal("second Close:", err)
	}
}

func TestCanariesRun(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc/self/exe is Linux only")
	}
	if err := canaryOpen(); err != nil {
		t.Fatal("open:", err)
	}
	if err := canaryExec(); err != nil {
		t.Fatal("exec:", err)
	}
}

// TestExecutedMatchesActiveLSMList attaches the real dispatchers of both hook
// types — the two BPF-LSM programs with their open and exec canaries, and the
// fmod_ret file_open program — and
// checks the run counter against the kernel's own answer. The invariant: a
// BPF-LSM program executes exactly when "bpf" is in the active LSM list. A
// CONFIG_BPF_LSM=y kernel booted without it still accepts the attach, so
// attach success must never be read as proof; the fmod_ret dispatcher, which
// has no such gate, must always execute.
func TestExecutedMatchesActiveLSMList(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}
	wantLSM, err := utils.BpfLSMEnabled()
	if err != nil {
		t.Skipf("cannot determine whether BPF-LSM is active: %v", err)
	}
	stats, err := EnableRunStats()
	if err != nil {
		t.Skip(err)
	}
	defer stats.Close()

	for _, tt := range []struct {
		target string
		want   bool
	}{
		{PROG_TYPE_LSM_OPEN, wantLSM},
		{PROG_TYPE_LSM_EXEC, wantLSM},
		{PROG_TYPE_TRACE_OPEN, true},
	} {
		t.Run(tt.target, func(t *testing.T) {
			if err := ClearPins(); err != nil {
				t.Fatal(err)
			}
			d, err := NewDispatcherForTarget(tt.target)
			if err != nil {
				t.Skipf("load: %v", err)
			}
			defer func() {
				if err := d.Close(); err != nil {
					t.Error(err)
				}
				_ = ClearPins()
			}()
			if err := d.Attach(); err != nil {
				t.Skipf("attach: %v", err)
			}
			ran, err := d.Executed(d.Canary())
			if err != nil {
				t.Fatal(err)
			}
			if ran != tt.want {
				t.Fatalf("executed=%t, want %t (bpf in LSM list: %t)", ran, tt.want, wantLSM)
			}
		})
	}
}
