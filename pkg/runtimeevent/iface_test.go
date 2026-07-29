package runtimeevent

import (
	"context"
	"errors"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeSource records how many times Run was called and returns a fixed error.
type fakeSource struct {
	name string
	err  error
	runs int
	sent []Event
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Run(ctx context.Context, out chan<- Event) error {
	f.runs++
	for _, ev := range f.sent {
		select {
		case out <- ev:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return f.err
}

// fakeSink records the events it handled.
type fakeSink struct {
	name string
	got  []Event
}

func (f *fakeSink) Name() string         { return f.name }
func (f *fakeSink) HandleEvent(ev Event) { f.got = append(f.got, ev) }

// fakeRecorder records status callbacks.
type fakeRecorder struct {
	violations [][2]string
	conditions map[string][]metav1.Condition
}

func (f *fakeRecorder) RecordViolation(policyUID, podUID string) {
	f.violations = append(f.violations, [2]string{policyUID, podUID})
}

func (f *fakeRecorder) RecordCondition(policyUID string, cond metav1.Condition) {
	if f.conditions == nil {
		f.conditions = map[string][]metav1.Condition{}
	}
	f.conditions[policyUID] = append(f.conditions[policyUID], cond)
}

var (
	_ Source               = (*fakeSource)(nil)
	_ Sink                 = (*fakeSink)(nil)
	_ PolicyStatusRecorder = (*fakeRecorder)(nil)
)

func TestSourceSinkSeamsAreImplementable(t *testing.T) {
	src := &fakeSource{name: "fake", sent: []Event{{Kind: KindOpen, Open: &OpenFacts{Path: "/etc/hosts"}}}}
	sink := &fakeSink{name: "sink"}

	out := make(chan Event, 1)
	if err := src.Run(context.Background(), out); err != nil {
		t.Fatalf("Run: %v", err)
	}
	close(out)
	for ev := range out {
		sink.HandleEvent(ev)
	}
	if len(sink.got) != 1 || sink.got[0].Open.Path != "/etc/hosts" {
		t.Errorf("sink got %+v, want one open event for /etc/hosts", sink.got)
	}
	if src.runs != 1 {
		t.Errorf("runs = %d, want 1", src.runs)
	}
}

func TestErrSourceNotWiredIsMatchableWhenWrapped(t *testing.T) {
	src := &fakeSource{name: "dnstrace", err: fmt.Errorf("starting %s: %w", "dnstrace", ErrSourceNotWired)}
	err := src.Run(context.Background(), make(chan Event, 1))
	if !errors.Is(err, ErrSourceNotWired) {
		t.Errorf("errors.Is(%v, ErrSourceNotWired) = false, want true", err)
	}
}

func TestPolicyStatusRecorderSeam(t *testing.T) {
	var rec PolicyStatusRecorder = &fakeRecorder{}
	rec.RecordViolation("policy-uid", "pod-uid")
	rec.RecordCondition("policy-uid", metav1.Condition{Type: "Applied", Status: metav1.ConditionTrue, Reason: "Monitoring"})

	f := rec.(*fakeRecorder)
	if len(f.violations) != 1 || f.violations[0] != [2]string{"policy-uid", "pod-uid"} {
		t.Errorf("violations = %v, want one (policy-uid, pod-uid)", f.violations)
	}
	if got := f.conditions["policy-uid"]; len(got) != 1 || got[0].Type != "Applied" {
		t.Errorf("conditions = %v, want one Applied condition", got)
	}
}
