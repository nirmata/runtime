package openexec

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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

// TestCanariesRun drives both canaries against fixtures, not the real procfs:
// a temp file for the open canary and the test binary itself for the exec
// canary, whose --help exits non-zero and must still count as an exec.
func TestCanariesRun(t *testing.T) {
	file := filepath.Join(t.TempDir(), "canary")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		target string
		path   string
	}{
		{PROG_TYPE_LSM_OPEN, file},
		{PROG_TYPE_TRACE_OPEN, file},
		{PROG_TYPE_LSM_EXEC, exe},
	} {
		d := &Dispatcher{dispatcherType: tt.target, canaryTarget: tt.path}
		if err := d.Canary()(); err != nil {
			t.Fatalf("%s canary: %v", tt.target, err)
		}
	}
	if err := canaryOpen(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a canary that could not open its target reported success")
	}
}

func TestCanaryDefaultsToRunningBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc/self/exe is Linux only")
	}
	d := &Dispatcher{dispatcherType: PROG_TYPE_LSM_OPEN}
	if err := d.Canary()(); err != nil {
		t.Fatalf("default open canary: %v", err)
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

// fakeClock advances only when executed sleeps, so the deadline path runs in
// no real time and the number of polls is exact.
type fakeClock struct {
	t      time.Time
	sleeps int
}

func (c *fakeClock) clock() runClock {
	return runClock{
		now:   func() time.Time { return c.t },
		sleep: func(d time.Duration) { c.t = c.t.Add(d); c.sleeps++ },
	}
}

func counter(values ...uint64) func() (uint64, error) {
	i := 0
	return func() (uint64, error) {
		v := values[min(i, len(values)-1)]
		i++
		return v, nil
	}
}

func TestExecutedReportsGhostWhenCounterNeverMoves(t *testing.T) {
	c := &fakeClock{}
	triggered := false
	ran, err := executed("file_open", counter(7), func() error { triggered = true; return nil }, c.clock())
	if err != nil || ran {
		t.Fatalf("ran=%t err=%v, want false: the counter never moved", ran, err)
	}
	if !triggered {
		t.Fatal("the canary was not run")
	}
	if want := int(executedWait/executedPoll) + 1; c.sleeps != want {
		t.Fatalf("polled %d times, want %d: the whole deadline must be waited out before declaring a ghost", c.sleeps, want)
	}
}

func TestExecutedReportsLiveOnceCounterMoves(t *testing.T) {
	c := &fakeClock{}
	ran, err := executed("file_open", counter(7, 7, 7, 9), nil2, c.clock())
	if err != nil || !ran {
		t.Fatalf("ran=%t err=%v, want true", ran, err)
	}
	if c.sleeps != 2 {
		t.Fatalf("polled %d times, want 2: return as soon as the counter moves", c.sleeps)
	}
}

func TestExecutedCountsOnlyRunsAfterTheBaseline(t *testing.T) {
	// a counter already high before the canary is not evidence: only growth is
	c := &fakeClock{}
	ran, _ := executed("file_open", counter(1000), nil2, c.clock())
	if ran {
		t.Fatal("a large but unchanging counter was read as executed")
	}
}

func TestExecutedPropagatesTriggerAndReadErrors(t *testing.T) {
	c := &fakeClock{}
	if _, err := executed("file_open", counter(1), func() error { return errors.New("open: EACCES") }, c.clock()); err == nil {
		t.Fatal("trigger error was swallowed")
	}
	reads := 0
	readErr := func() (uint64, error) {
		reads++
		if reads == 2 {
			return 0, errors.New("stats: EPERM")
		}
		return 1, nil
	}
	if _, err := executed("file_open", readErr, nil2, c.clock()); err == nil {
		t.Fatal("counter read error was swallowed")
	}
}

func nil2() error { return nil }
