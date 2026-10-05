package openexecmgr

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/events"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type fakeHooks struct {
	lsm      bool
	ran      bool
	ranErr   error
	closeErr error
	closed   bool
	executed bool
}

func (f *fakeHooks) Executed() (bool, error) { f.executed = true; return f.ran, f.ranErr }
func (f *fakeHooks) Close() error            { f.closed = true; return f.closeErr }

// fakeAttach hands out one fakeHooks per hook type and records the order the
// types were tried in. A nil entry means that type fails to attach.
type fakeAttach struct {
	sets      map[bool]*fakeHooks
	attachErr map[bool]error
	tried     []bool
}

func (a *fakeAttach) attach(lsm bool) (hookSet, error) {
	a.tried = append(a.tried, lsm)
	if err := a.attachErr[lsm]; err != nil {
		return nil, err
	}
	hs := a.sets[lsm]
	if hs == nil {
		return nil, errors.New("attach refused")
	}
	return hs, nil
}

func TestSelectHooksKeepsPreferredSetWhenItExecutes(t *testing.T) {
	a := &fakeAttach{sets: map[bool]*fakeHooks{true: {lsm: true, ran: true}, false: {ran: true}}}
	hs, lsm, err := selectHooks(logr.Discard(), true, true, a.attach)
	if err != nil {
		t.Fatal(err)
	}
	if !lsm || hs != a.sets[true] {
		t.Fatalf("selected lsm=%t %p, want the BPF-LSM set", lsm, hs)
	}
	if len(a.tried) != 1 {
		t.Fatalf("tried %v, want only the preferred type", a.tried)
	}
}

// TestSelectHooksFallsBackWhenPreferredSetNeverExecutes pins the invariant
// that attach success is not selection: a set whose programs attach without
// error but never run must be torn down and the other set selected instead.
func TestSelectHooksFallsBackWhenPreferredSetNeverExecutes(t *testing.T) {
	ghost := &fakeHooks{lsm: true, ran: false}
	a := &fakeAttach{sets: map[bool]*fakeHooks{true: ghost, false: {ran: true}}}
	hs, lsm, err := selectHooks(logr.Discard(), true, true, a.attach)
	if err != nil {
		t.Fatal(err)
	}
	if lsm || hs != a.sets[false] {
		t.Fatalf("selected lsm=%t, want the fmod_ret set", lsm)
	}
	if !ghost.closed {
		t.Fatal("the ghost set was left attached")
	}
}

func TestSelectHooksTriesOtherSetWhenPreferredDoesNotAttach(t *testing.T) {
	a := &fakeAttach{sets: map[bool]*fakeHooks{true: {lsm: true, ran: true}}}
	_, lsm, err := selectHooks(logr.Discard(), false, true, a.attach)
	if err != nil {
		t.Fatal(err)
	}
	if !lsm {
		t.Fatal("selected fmod_ret although it did not attach")
	}
	if len(a.tried) != 2 || a.tried[0] != false {
		t.Fatalf("tried %v, want fmod_ret first then BPF-LSM", a.tried)
	}
}

func TestSelectHooksFailsWhenNoSetExecutes(t *testing.T) {
	a := &fakeAttach{sets: map[bool]*fakeHooks{true: {lsm: true}, false: {}}}
	if _, _, err := selectHooks(logr.Discard(), true, true, a.attach); err == nil {
		t.Fatal("two ghost sets selected one of them")
	}
	for lsm, hs := range a.sets {
		if !hs.closed {
			t.Errorf("lsm=%t set left attached", lsm)
		}
	}
}

func TestSelectHooksTreatsCanaryErrorLikeAttachFailure(t *testing.T) {
	broken := &fakeHooks{lsm: true, ranErr: errors.New("stats: EPERM")}
	a := &fakeAttach{sets: map[bool]*fakeHooks{true: broken, false: {ran: true}}}
	_, lsm, err := selectHooks(logr.Discard(), true, true, a.attach)
	if err != nil {
		t.Fatal(err)
	}
	if lsm || !broken.closed {
		t.Fatalf("lsm=%t closed=%t, want fmod_ret with the broken set closed", lsm, broken.closed)
	}
}

// Without run statistics nothing can be verified, so selection must fall back
// to exactly the pre-verification behavior: attach what the LSM list suggests
// and accept it. It must not try the other hook type, because accepting that
// one on attach success alone is how a ghost attach would be selected.
func TestSelectHooksWithoutVerificationOnlyTriesPreferredSet(t *testing.T) {
	preferred := &fakeHooks{lsm: true}
	a := &fakeAttach{sets: map[bool]*fakeHooks{true: preferred, false: {ran: true}}}
	_, lsm, err := selectHooks(logr.Discard(), true, false, a.attach)
	if err != nil {
		t.Fatal(err)
	}
	if !lsm || preferred.executed {
		t.Fatalf("lsm=%t executed=%t, want the preferred attach kept without a canary", lsm, preferred.executed)
	}
	if len(a.tried) != 1 {
		t.Fatalf("tried %v, want only the preferred type", a.tried)
	}
}

func TestSelectHooksWithoutVerificationDoesNotFallBack(t *testing.T) {
	a := &fakeAttach{sets: map[bool]*fakeHooks{true: {lsm: true, ran: true}}}
	_, _, err := selectHooks(logr.Discard(), false, false, a.attach)
	if !errors.Is(err, ErrNoHookExecutes) {
		t.Fatalf("err = %v, want ErrNoHookExecutes: the unverifiable alternative must not be selected", err)
	}
	if len(a.tried) != 1 {
		t.Fatalf("tried %v, want only the preferred type", a.tried)
	}
}

// A node with no executing hook type must not read as Enforcing: the manager
// still handles policy events, and every policy that needs an open or exec
// enforcer gets EnforcementAvailable (or ObservationAvailable) = False naming
// the cause.
func TestUnavailableHooksPutEnforcementUnavailableOnPolicies(t *testing.T) {
	cause := fmt.Errorf("%w: bpf-lsm: programs attached but never executed", ErrNoHookExecutes)
	for _, tt := range []struct {
		mode string
		want string
	}{
		{compiler.ModeEnforce, v1alpha1.ConditionEnforcementAvailable},
		{compiler.ModeMonitor, v1alpha1.ConditionObservationAvailable},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			status := newFakeStatus()
			l := newUnavailableOpenExecManager(logr.Discard(), status, nil, false, cause)
			if l.HooksUnavailable() != cause {
				t.Fatal("HooksUnavailable did not return the cause")
			}
			rp := result("rp1", tt.mode, labels.Everything(), pair(nil, []string{"/etc/shadow"}), nil)
			if err := l.RuntimePolicyEvent(rp, events.EventTypeCreate); err == nil {
				t.Fatal("expected the failure to propagate so the event is requeued")
			}
			got := condOfType(t, status, "rp1", tt.want)
			if got.Status != metav1.ConditionFalse {
				t.Fatalf("%s = %v, want False", tt.want, got.Status)
			}
			if !strings.Contains(got.Message, ErrNoHookExecutes.Error()) {
				t.Fatalf("message %q does not name the cause", got.Message)
			}
		})
	}
}

// A rejected set that cannot be confirmed detached ends selection: attaching
// the other set next to the remains of the first would leave two dispatchers
// on one hook with cleared pins, which is worse than reporting no enforcement.
func TestSelectHooksStopsWhenTeardownOfRejectedSetFails(t *testing.T) {
	ghost := &fakeHooks{lsm: true, closeErr: errors.New("link close: EBUSY")}
	a := &fakeAttach{sets: map[bool]*fakeHooks{true: ghost, false: {ran: true}}}
	_, _, err := selectHooks(logr.Discard(), true, true, a.attach)
	if !errors.Is(err, ErrNoHookExecutes) || !errors.Is(err, errTeardown) {
		t.Fatalf("err = %v, want ErrNoHookExecutes wrapping errTeardown", err)
	}
	if len(a.tried) != 1 {
		t.Fatalf("tried %v, want no attempt at the other set after a failed teardown", a.tried)
	}
}

func TestSelectHooksStopsWhenPartialAttachCannotBeTornDown(t *testing.T) {
	a := &fakeAttach{sets: map[bool]*fakeHooks{false: {ran: true}}, attachErr: map[bool]error{true: fmt.Errorf("%w: unlink", errTeardown)}}
	_, _, err := selectHooks(logr.Discard(), true, true, a.attach)
	if !errors.Is(err, errTeardown) {
		t.Fatalf("err = %v, want errTeardown to end selection", err)
	}
	if len(a.tried) != 1 {
		t.Fatalf("tried %v, want no fallback after a failed partial teardown", a.tried)
	}
}
