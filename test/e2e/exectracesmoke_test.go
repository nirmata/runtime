package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/exectrace"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
)

// selfCgroupID resolves this process's cgroup to the id bpf_get_current_cgroup_id
// returns, which is the v2 directory's inode number.
func selfCgroupID(t *testing.T) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatalf("reading /proc/self/cgroup: %v", err)
	}
	// A hybrid or cgroup v1 host lists one line per controller, so the unified
	// entry has to be picked out by its empty controller field rather than by
	// splitting the whole file — which on those hosts yields a path with
	// newlines in it and an unnecessary skip.
	var unified string
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(fields) == 3 && fields[0] == "0" && fields[1] == "" {
			unified = fields[2]
			break
		}
	}
	if unified == "" {
		t.Skipf("no cgroup v2 line in /proc/self/cgroup: %q", b)
	}
	fi, err := os.Stat("/sys/fs/cgroup" + unified)
	if err != nil {
		t.Skipf("cgroup v2 path not present: %v", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("cgroup stat has no inode")
	}
	return st.Ino
}

// TestBPFExecTraceReportsArgv loads and attaches the committed exectrace object
// and asserts that a real execve in an admitted cgroup arrives decoded, with the
// argv the kernel actually recorded. Synthetic bytes cannot make that assertion:
// the layout agreement between _cprog/maps.h and decode.go is only proven by a
// record the kernel itself wrote.
func TestBPFExecTraceReportsArgv(t *testing.T) {
	requireBPFCapableHost(t)

	src, err := exectrace.New(testr.New(t), time.Second)
	if err != nil {
		// %+v renders *ebpf.VerifierError's full log.
		t.Fatalf("loading exectrace objects: %+v", err)
	}
	t.Cleanup(func() { src.Close() })

	cgid := selfCgroupID(t)
	if err := src.AddCgids([]uint64{cgid}); err != nil {
		t.Fatalf("admitting cgroup %d: %v", cgid, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out := make(chan runtimeevent.Event, 64)
	runErr := make(chan error, 1)
	go func() { runErr <- src.Run(ctx, out) }()

	// The ring buffer only carries execs that happen after the attach, and Run
	// races the first exec, so retry until the deadline.
	want := []string{"/bin/echo", "mcp-probe", "alpha"}
	deadline := time.After(20 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var got *runtimeevent.Event
	for got == nil {
		select {
		case <-deadline:
			t.Fatal("no matching exec event observed before the deadline")
		case <-ticker.C:
			_ = exec.Command(want[0], want[1:]...).Run()
		case ev := <-out:
			if ev.Kind != runtimeevent.KindExec || ev.Exec == nil {
				t.Fatalf("expected an exec event, got kind %q", ev.Kind)
			}
			if ev.Exec.Filename == want[0] && len(ev.Exec.Argv) == len(want) {
				e := ev
				got = &e
			}
		}
	}

	if got.CgroupID != cgid {
		t.Errorf("cgroup id = %d, want %d (the gate admitted the wrong cgroup)", got.CgroupID, cgid)
	}
	for i, arg := range want {
		if got.Exec.Argv[i] != arg {
			t.Errorf("argv[%d] = %q, want %q", i, got.Exec.Argv[i], arg)
		}
	}
	if got.PID == 0 {
		t.Error("pid is zero")
	}
	if got.Comm == "" {
		t.Error("comm is empty")
	}
	if got.Time.IsZero() {
		t.Error("the source did not stamp the event")
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Errorf("Run returned %v, want nil on context cancel", err)
	}
}

// TestBPFExecTraceIgnoresUnadmittedCgroups pins the kernel-side gate: without a
// cgroup id in the map the program returns before reserving, so an exec in an
// unadmitted cgroup must produce nothing at all.
func TestBPFExecTraceIgnoresUnadmittedCgroups(t *testing.T) {
	requireBPFCapableHost(t)

	// 0 exercises the non-positive clamp; this test never reads the counters.
	src, err := exectrace.New(logr.Discard(), 0)
	if err != nil {
		t.Fatalf("loading exectrace objects: %+v", err)
	}
	t.Cleanup(func() { src.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan runtimeevent.Event, 16)
	go func() { _ = src.Run(ctx, out) }()

	time.Sleep(500 * time.Millisecond)
	for i := 0; i < 5; i++ {
		_ = exec.Command("/bin/echo", "unadmitted").Run()
	}

	select {
	case ev := <-out:
		t.Fatalf("observed an exec from an unadmitted cgroup: %+v", ev.Exec)
	case <-time.After(2 * time.Second):
	}
}
