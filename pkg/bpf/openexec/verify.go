package openexec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/cilium/ebpf"
)

// Attach success does not prove a program runs. A kernel built with
// CONFIG_BPF_LSM=y accepts an LSM attach even when "bpf" is absent from the
// active LSM list (the lsm= boot parameter), and then never calls the program:
// the link exists, bpftool shows it, and the hook enforces nothing. The
// kernel's own per-program run counter is the one signal that separates an
// attach that executes from one that does not.

// ErrRunStatsUnavailable means the kernel cannot count program runs here
// (Linux < 5.8, or missing CAP_SYS_ADMIN), so execution cannot be verified.
var ErrRunStatsUnavailable = errors.New("bpf run statistics unavailable")

// executedWait bounds how long Executed waits for the counter to move after
// the canary completes. The kernel updates it on the program's return path, so
// a live program shows up within a few scheduler ticks.
const executedWait = 500 * time.Millisecond

// bpfStatsRunTime is BPF_STATS_RUN_TIME from linux/bpf.h, the only statistics
// type the kernel defines. x/sys/unix exposes it on Linux only.
const bpfStatsRunTime = 0

// EnableRunStats turns on run accounting for every loaded BPF program until the
// returned closer is called. Accounting costs a timestamp per program run, so
// callers keep it on only around verification.
func EnableRunStats() (io.Closer, error) {
	c, err := ebpf.EnableStats(bpfStatsRunTime)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunStatsUnavailable, err)
	}
	return c, nil
}

// runClock is the time source executed polls with. Tests replace it so the
// deadline path runs without waiting.
type runClock struct {
	now   func() time.Time
	sleep func(time.Duration)
}

var realClock = runClock{now: time.Now, sleep: time.Sleep}

// executedPoll is how often the counter is re-read before the deadline.
const executedPoll = 10 * time.Millisecond

// Executed reports whether the dispatcher's program ran at least once between a
// run-count read and the completion of trigger. Run statistics must be enabled
// while it runs, or the counter never moves and a live hook reads as dead. A
// target that carries no program of its own (the fmod_ret exec target) is
// covered by the file_open dispatcher and reports true.
//
// The counter is the kernel's per-program total, so it does not say which
// event caused an increment — and it does not need to. The question is whether
// the kernel calls this program at all: a ghost attach is never invoked, by
// anything, so its counter cannot move however busy the node is; a program that
// ran for some other process's open runs for the workload's too, since it is
// the same hook. Unrelated traffic can only make a live verdict arrive sooner.
// The trigger exists so a live program on an idle node is not misread as a
// ghost for want of any event in the window.
func (d *Dispatcher) Executed(trigger func() error) (bool, error) {
	if d.prog == nil {
		return true, nil
	}
	readCount := func() (uint64, error) {
		s, err := d.prog.Stats()
		if err != nil {
			return 0, fmt.Errorf("reading %s run count: %w", d.dispatcherType, err)
		}
		return s.RunCount, nil
	}
	return executed(d.dispatcherType, readCount, trigger, realClock)
}

// executed is Executed with its kernel and time dependencies injected: read
// the counter, run the trigger, then poll the counter until it moves or the
// deadline passes.
//
// A trigger that fails is not evidence of a ghost: another LSM or a permission
// check may reject the canary's open or exec after this program already ran
// for it, so the counter is polled regardless. It decides when it moves; when
// it does not, the trigger error is returned rather than a ghost verdict,
// because nothing is known about a hook whose canary never happened.
func executed(name string, readCount func() (uint64, error), trigger func() error, clk runClock) (bool, error) {
	before, err := readCount()
	if err != nil {
		return false, err
	}
	triggerErr := trigger()
	deadline := clk.now().Add(executedWait)
	for {
		after, err := readCount()
		if err != nil {
			return false, err
		}
		if after > before {
			return true, nil
		}
		if clk.now().After(deadline) {
			if triggerErr != nil {
				return false, fmt.Errorf("canary for %s: %w", name, triggerErr)
			}
			return false, nil
		}
		clk.sleep(executedPoll)
	}
}

// selfExe is the default canary target: the running binary always exists, needs
// neither write access nor a temp directory, and is executable.
const selfExe = "/proc/self/exe"

// Canary returns an action that passes through this dispatcher's hook and
// changes nothing on the node. The target defaults to the running binary;
// tests point canaryTarget at a fixture instead of the real procfs.
func (d *Dispatcher) Canary() func() error {
	target := d.canaryPath()
	if d.dispatcherType == PROG_TYPE_LSM_EXEC {
		return func() error { return canaryExec(target) }
	}
	return func() error { return canaryOpen(target) }
}

// canaryPath is the file the canary acts on: canaryTarget when set, else the
// running binary.
func (d *Dispatcher) canaryPath() string {
	if d.canaryTarget != "" {
		return d.canaryTarget
	}
	return selfExe
}

// canaryOpen opens path read-only: every open passes security_file_open.
func canaryOpen(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return f.Close()
}

// canaryExec executes path with --help, which for the daemon exits at once.
// Every execve passes bprm_check_security, so the exit status is irrelevant:
// a non-zero exit still means the exec happened.
func canaryExec(path string) error {
	cmd := exec.Command(path, "--help")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil
	}
	return err
}
