package openexecmgr

import (
	"errors"
	"fmt"
	"sort"

	"github.com/nirmata/runtime/pkg/bpf/openexec"

	"github.com/go-logr/logr"
)

// ErrNoHookExecutes means neither the BPF-LSM nor the fmod_ret dispatchers
// could be attached and shown to run, so no open or exec rule can be enforced
// or observed on this node.
var ErrNoHookExecutes = errors.New("no open/exec hook executes on this node")

// errTeardown marks a hook set that was rejected but could not be confirmed
// detached. Selection stops on it rather than attaching a second set next to
// the remains of the first.
var errTeardown = errors.New("teardown of a rejected open/exec hook set failed")

// hookSet is one attached candidate: the dispatchers of either the BPF-LSM
// targets or the fmod_ret targets.
type hookSet interface {
	// Executed runs each dispatcher's canary and reports whether every program
	// that was attached actually ran.
	Executed() (bool, error)
	Close() error
}

type attachFunc func(lsm bool) (hookSet, error)

// hookTypeName is the operator-facing name of a hook type.
func hookTypeName(lsm bool) string {
	if lsm {
		return "bpf-lsm"
	}
	return "fmod_ret"
}

// selectHooks attaches the BPF-LSM and fmod_ret hook sets in turn, the one the
// active LSM list suggests first, and returns the first whose programs are
// proven to execute. Attach success alone is not proof: a kernel with
// CONFIG_BPF_LSM=y accepts an LSM attach without "bpf" in its LSM list and then
// never runs the program (see openexec.Executed). A set that does not attach,
// or attaches without executing, is torn down before the other is tried.
//
// With verify false — run statistics unavailable, because the kernel predates
// 5.8 or the daemon lacks CAP_SYS_ADMIN — only the set the LSM list suggests
// is attached, and it is accepted on attach success without any execution
// check. The other set is never tried: accepting it without proof is how a
// ghost attach would slip through.
//
// A rejected set must be confirmed gone before the other is tried; a teardown
// failure ends selection with the error, since two dispatchers on one hook
// with cleared pins is worse than no enforcement.
func selectHooks(logger logr.Logger, preferLSM, verify bool, attach attachFunc) (hookSet, bool, error) {
	candidates := []bool{preferLSM, !preferLSM}
	if !verify {
		candidates = candidates[:1]
	}
	var errs []error
	for _, lsm := range candidates {
		hs, err := attach(lsm)
		if err != nil {
			if errors.Is(err, errTeardown) {
				return nil, false, fmt.Errorf("%w: %w", ErrNoHookExecutes, errors.Join(append(errs, err)...))
			}
			logger.V(1).Info("open/exec hooks did not attach", "hookType", hookTypeName(lsm), "reason", err.Error())
			errs = append(errs, err)
			continue
		}
		if !verify {
			logger.Info("open/exec hooks attached but not verified: bpf run statistics unavailable, so the other hook type is not tried",
				"hookType", hookTypeName(lsm))
			return hs, lsm, nil
		}
		ran, err := hs.Executed()
		if err == nil && ran {
			return hs, lsm, nil
		}
		if err == nil {
			logger.Info("open/exec hooks attached but never executed: the kernel accepted the attach without wiring the hook",
				"hookType", hookTypeName(lsm))
			err = fmt.Errorf("%s: programs attached but never executed", hookTypeName(lsm))
		}
		errs = append(errs, err)
		if cerr := hs.Close(); cerr != nil {
			errs = append(errs, fmt.Errorf("%w: %w", errTeardown, cerr))
			return nil, false, fmt.Errorf("%w: %w", ErrNoHookExecutes, errors.Join(errs...))
		}
	}
	return nil, false, fmt.Errorf("%w: %w", ErrNoHookExecutes, errors.Join(errs...))
}

// unavailableEnforcer is the enforcer factory of a manager with no working
// hooks. Every policy that needs an open or exec enforcer fails to create it
// with cause, which the existing attach-failure path turns into an
// EnforcementAvailable / ObservationAvailable = False condition on that
// policy, so a node that can enforce nothing does not read as Enforcing.
func unavailableEnforcer(cause error) enforcerFactory {
	return func(_ *logr.Logger, target string) (openExecMap, error) {
		return nil, fmt.Errorf("no enforcer for %s: %w", target, cause)
	}
}

// dispatcherSet is the hookSet of real kernel dispatchers, keyed by target.
type dispatcherSet map[string]*openexec.Dispatcher

// attachDispatchers loads and attaches the dispatcher of every target of one
// hook type. On any failure what was attached so far is released.
func attachDispatchers(lsm bool) (hookSet, error) {
	targets := []string{openexec.PROG_TYPE_TRACE_OPEN, openexec.PROG_TYPE_TRACE_EXEC}
	if lsm {
		targets = []string{openexec.PROG_TYPE_LSM_OPEN, openexec.PROG_TYPE_LSM_EXEC}
	}
	set := make(dispatcherSet, len(targets))
	for _, target := range targets {
		d, err := openexec.NewDispatcherForTarget(target)
		if err != nil {
			return nil, set.abandon(fmt.Errorf("loading the %s dispatcher: %w", target, err))
		}
		set[target] = d
		if err := d.Attach(); err != nil {
			return nil, set.abandon(fmt.Errorf("attaching the %s dispatcher: %w", target, err))
		}
	}
	return set, nil
}

// abandon releases a partially attached set after cause. A teardown failure is
// reported as errTeardown so selection stops instead of trying the other set.
func (s dispatcherSet) abandon(cause error) error {
	if cerr := s.Close(); cerr != nil {
		return fmt.Errorf("%w: %w (after: %v)", errTeardown, cerr, cause)
	}
	return cause
}

func (s dispatcherSet) Executed() (bool, error) {
	for _, d := range s {
		ran, err := d.Executed(d.Canary())
		if err != nil || !ran {
			return false, err
		}
	}
	return true, nil
}

// Close releases every dispatcher and then the pins they shared, so the next
// hook type starts from empty maps rather than inheriting this one's. The pins
// are cleared only once every dispatcher is closed: a dispatcher that kept a
// handle after a failed close still owns maps behind those pins, and a retry
// of Close needs them in place.
func (s dispatcherSet) Close() error {
	errs := make([]error, 0, len(s)+1)
	for _, d := range s {
		errs = append(errs, d.Close())
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return openexec.ClearPins()
}

func (s dispatcherSet) targets() []string {
	out := make([]string, 0, len(s))
	for t := range s {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
