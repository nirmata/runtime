package openexecmgr

import (
	"errors"
	"testing"

	"github.com/go-logr/logr"
)

type fakeHooks struct {
	lsm      bool
	ran      bool
	ranErr   error
	closed   bool
	executed bool
}

func (f *fakeHooks) Executed() (bool, error) { f.executed = true; return f.ran, f.ranErr }
func (f *fakeHooks) Close() error            { f.closed = true; return nil }

// fakeAttach hands out one fakeHooks per hook type and records the order the
// types were tried in. A nil entry means that type fails to attach.
type fakeAttach struct {
	sets  map[bool]*fakeHooks
	tried []bool
}

func (a *fakeAttach) attach(lsm bool) (hookSet, error) {
	a.tried = append(a.tried, lsm)
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

// TestSelectHooksFallsBackWhenPreferredSetNeverExecutes pins #230's ghost
// attach: the BPF-LSM programs attach without error but never run, so the set
// must be torn down and fmod_ret selected instead.
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

func TestSelectHooksWithoutVerificationAcceptsFirstAttach(t *testing.T) {
	ghost := &fakeHooks{lsm: true}
	a := &fakeAttach{sets: map[bool]*fakeHooks{true: ghost, false: {ran: true}}}
	_, lsm, err := selectHooks(logr.Discard(), true, false, a.attach)
	if err != nil {
		t.Fatal(err)
	}
	if !lsm || ghost.executed {
		t.Fatalf("lsm=%t executed=%t, want the first attach kept without a canary", lsm, ghost.executed)
	}
}
