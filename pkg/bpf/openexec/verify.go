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

// Executed reports whether the dispatcher's program ran at least once between a
// run-count read and the completion of trigger. Run statistics must be enabled
// while it runs, or the counter never moves and a live hook reads as dead. A
// target that carries no program of its own (the fmod_ret exec target) is
// covered by the file_open dispatcher and reports true.
func (d *Dispatcher) Executed(trigger func() error) (bool, error) {
	if d.prog == nil {
		return true, nil
	}
	before, err := d.prog.Stats()
	if err != nil {
		return false, fmt.Errorf("reading %s run count: %w", d.dispatcherType, err)
	}
	if err := trigger(); err != nil {
		return false, fmt.Errorf("canary for %s: %w", d.dispatcherType, err)
	}
	deadline := time.Now().Add(executedWait)
	for {
		after, err := d.prog.Stats()
		if err != nil {
			return false, fmt.Errorf("reading %s run count: %w", d.dispatcherType, err)
		}
		if after.RunCount > before.RunCount {
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Canary returns an action that passes through this dispatcher's hook and
// changes nothing on the node.
func (d *Dispatcher) Canary() func() error {
	if d.dispatcherType == PROG_TYPE_LSM_EXEC {
		return canaryExec
	}
	return canaryOpen
}

// canaryOpen opens the running binary itself: it always exists, needs neither
// write access nor a temp directory, and every open passes security_file_open.
func canaryOpen() error {
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	return f.Close()
}

// canaryExec executes the running binary with --help, which exits at once.
// Every execve passes bprm_check_security, so the exit status is irrelevant:
// a non-zero exit still means the exec happened.
func canaryExec() error {
	cmd := exec.Command("/proc/self/exe", "--help")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil
	}
	return err
}
