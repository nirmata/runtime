package controller

import (
	"slices"
	"testing"

	"github.com/nirmata/runtime/api/v1alpha1"
	fakeversioned "github.com/nirmata/runtime/pkg/client/clientset/versioned/fake"
	"github.com/nirmata/runtime/pkg/events"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type fakeNotifier struct {
	handlers []func(namespace, name string)
}

func (f *fakeNotifier) AddChangeHandler(h func(namespace, name string)) {
	f.handlers = append(f.handlers, h)
}

func svcValue(namespace, name string) string {
	return name + "." + namespace + ".svc.cluster.local"
}

func netPolicy(name string, behaviors ...v1alpha1.PolicyBehavior) *v1alpha1.RuntimePolicy {
	return &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name)},
		Spec:       v1alpha1.RuntimePolicySpec{Behaviors: behaviors},
	}
}

func networkBehavior(allow, deny *v1alpha1.BehaviorRule) v1alpha1.PolicyBehavior {
	return v1alpha1.PolicyBehavior{Network: &v1alpha1.Behavior{Allow: allow, Deny: deny}}
}

func valueRule(values ...string) *v1alpha1.BehaviorRule {
	return &v1alpha1.BehaviorRule{Values: values}
}

func drainQueue(t *testing.T, m *RuntimePolicyMgr) []queueKey {
	t.Helper()
	keys := make([]queueKey, 0)
	for m.queue.Len() > 0 {
		key, quit := m.queue.Get()
		if quit {
			break
		}
		m.queue.Done(key)
		keys = append(keys, key)
	}
	return keys
}

func queuedNames(keys []queueKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Key)
	}
	slices.Sort(out)
	return out
}

func TestServiceChangedRequeuesOnlyTheReferencingPolicies(t *testing.T) {
	inAllow := netPolicy("in-allow", networkBehavior(valueRule(svcValue("prod", "api")), nil))
	inDeny := netPolicy("in-deny", networkBehavior(nil, valueRule(svcValue("prod", "api"))))
	secondBehavior := netPolicy("second-behavior",
		networkBehavior(valueRule(svcValue("prod", "other")), nil),
		networkBehavior(nil, valueRule(svcValue("staging", "cache"), svcValue("prod", "api"))),
	)
	literalsOnly := netPolicy("literals-only", networkBehavior(valueRule("1.1.1.1", "10.0.0.0/8", "*"), nil))
	externalName := netPolicy("external-name", networkBehavior(valueRule("api.prod.example.com"), nil))
	otherNamespace := netPolicy("other-namespace", networkBehavior(valueRule(svcValue("staging", "api")), nil))
	otherName := netPolicy("other-name", networkBehavior(valueRule(svcValue("prod", "web")), nil))
	malformed := netPolicy("malformed", networkBehavior(valueRule("api.prod.svc.other.example", "http://api/", "10.0.0"), nil))
	nonNetwork := netPolicy("non-network", v1alpha1.PolicyBehavior{
		Exec: &v1alpha1.Behavior{Allow: valueRule(svcValue("prod", "api"))},
	})
	noBehaviors := netPolicy("no-behaviors")

	m, _ := newTestRpMgr(t, &fakeCompiler{}, nil,
		inAllow, inDeny, secondBehavior, literalsOnly, externalName,
		otherNamespace, otherName, malformed, nonNetwork, noBehaviors)

	m.serviceChanged("prod", "api")

	keys := drainQueue(t, m)
	want := []string{"in-allow", "in-deny", "second-behavior"}
	if got := queuedNames(keys); !slices.Equal(got, want) {
		t.Fatalf("requeued policies: got %v, want %v", got, want)
	}
	for _, key := range keys {
		if key.Type != events.EventTypeUpdate {
			t.Errorf("policy %s was queued as %q, want %q", key.Key, key.Type, events.EventTypeUpdate)
		}
	}
}

func TestServiceChangedQueuesEachPolicyOnce(t *testing.T) {
	value := svcValue("prod", "api")
	twice := netPolicy("twice",
		networkBehavior(valueRule(value), valueRule(value)),
		networkBehavior(valueRule(value), nil),
	)

	m, _ := newTestRpMgr(t, &fakeCompiler{}, nil, twice)

	m.serviceChanged("prod", "api")

	if got := m.queue.Len(); got != 1 {
		t.Fatalf("queue length: got %d, want 1", got)
	}
}

func TestNewRuntimePolicyMgrRegistersTheServiceChangeHandler(t *testing.T) {
	notifier := &fakeNotifier{}
	m, err := NewRuntimePolicyMgr(nil, nil, fakeversioned.NewSimpleClientset(), &fakeCompiler{}, notifier, &fakeStatusRecorder{})
	if err != nil {
		t.Fatalf("NewRuntimePolicyMgr: %v", err)
	}
	t.Cleanup(m.queue.ShutDown)

	if len(notifier.handlers) != 1 {
		t.Fatalf("registered change handlers: got %d, want 1", len(notifier.handlers))
	}

	referencing := netPolicy("referencing", networkBehavior(valueRule(svcValue("prod", "api")), nil))
	if err := m.rpInformer.GetIndexer().Add(referencing); err != nil {
		t.Fatal(err)
	}

	notifier.handlers[0]("prod", "api")

	if got := queuedNames(drainQueue(t, m)); !slices.Equal(got, []string{"referencing"}) {
		t.Fatalf("requeued policies: got %v, want [referencing]", got)
	}
}
