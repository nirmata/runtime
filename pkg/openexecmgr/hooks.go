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
// With verify false — run statistics unavailable — only the set the LSM list
// suggests is attached, and it is accepted on attach success. That is the
// pre-verification behavior exactly; the other set is never tried, because
// accepting it without proof is how a ghost attach would slip through.
func selectHooks(logger logr.Logger, preferLSM, verify bool, attach attachFunc) (hookSet, bool, error) {
	candidates := []bool{preferLSM, !preferLSM}
	if !verify {
		candidates = candidates[:1]
	}
	var errs []error
	for _, lsm := range candidates {
		hs, err := attach(lsm)
		if err != nil {
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
		if err != nil {
			errs = append(errs, err, hs.Close())
			continue
		}
		if !ran {
			logger.Info("open/exec hooks attached but never executed: the kernel accepted the attach without wiring the hook",
				"hookType", hookTypeName(lsm))
			errs = append(errs, fmt.Errorf("%s: programs attached but never executed", hookTypeName(lsm)), hs.Close())
			continue
		}
		return hs, lsm, nil
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
			return nil, errors.Join(fmt.Errorf("loading the %s dispatcher: %w", target, err), set.Close())
		}
		set[target] = d
		if err := d.Attach(); err != nil {
			return nil, errors.Join(fmt.Errorf("attaching the %s dispatcher: %w", target, err), set.Close())
		}
	}
	return set, nil
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

// Close releases every dispatcher and the pins they shared, so the next hook
// type starts from empty maps rather than inheriting this one's.
func (s dispatcherSet) Close() error {
	errs := make([]error, 0, len(s)+1)
	for _, d := range s {
		errs = append(errs, d.Close())
	}
	errs = append(errs, openexec.ClearPins())
	return errors.Join(errs...)
}

func (s dispatcherSet) targets() []string {
	out := make([]string, 0, len(s))
	for t := range s {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
