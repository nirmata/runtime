package controller

import (
	"slices"
	"testing"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	fakeversioned "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned/fake"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type fakeNotifier struct {
	handlers []func(v1alpha1.ServiceReference)
}

func (f *fakeNotifier) AddChangeHandler(h func(ref v1alpha1.ServiceReference)) {
	f.handlers = append(f.handlers, h)
}

func svcRef(namespace, name string) v1alpha1.ServiceReference {
	return v1alpha1.ServiceReference{Namespace: namespace, Name: name}
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

func refRule(refs ...v1alpha1.ServiceReference) *v1alpha1.BehaviorRule {
	return &v1alpha1.BehaviorRule{ServiceRefs: refs}
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

func TestServiceRefChangedRequeuesOnlyTheReferencingPolicies(t *testing.T) {
	changed := svcRef("prod", "api")

	inAllow := netPolicy("in-allow", networkBehavior(refRule(changed), nil))
	inDeny := netPolicy("in-deny", networkBehavior(nil, refRule(changed)))
	secondBehavior := netPolicy("second-behavior",
		networkBehavior(refRule(svcRef("prod", "other")), nil),
		networkBehavior(nil, refRule(svcRef("staging", "cache"), changed)),
	)
	noRefs := netPolicy("no-refs", networkBehavior(&v1alpha1.BehaviorRule{Values: []string{"1.1.1.1"}}, nil))
	otherNamespace := netPolicy("other-namespace", networkBehavior(refRule(svcRef("staging", "api")), nil))
	otherName := netPolicy("other-name", networkBehavior(refRule(svcRef("prod", "web")), nil))
	nonNetwork := netPolicy("non-network", v1alpha1.PolicyBehavior{
		Exec: &v1alpha1.Behavior{Allow: refRule(changed)},
	})
	noBehaviors := netPolicy("no-behaviors")

	m, _ := newTestRpMgr(t, &fakeCompiler{}, nil,
		inAllow, inDeny, secondBehavior, noRefs, otherNamespace, otherName, nonNetwork, noBehaviors)

	m.serviceRefChanged(changed)

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

func TestServiceRefChangedQueuesEachPolicyOnce(t *testing.T) {
	changed := svcRef("prod", "api")
	twice := netPolicy("twice",
		networkBehavior(refRule(changed), refRule(changed)),
		networkBehavior(refRule(changed), nil),
	)

	m, _ := newTestRpMgr(t, &fakeCompiler{}, nil, twice)

	m.serviceRefChanged(changed)

	if got := m.queue.Len(); got != 1 {
		t.Fatalf("queue length: got %d, want 1", got)
	}
}

func TestNewRuntimePolicyMgrRegistersTheServiceChangeHandler(t *testing.T) {
	notifier := &fakeNotifier{}
	m, err := NewRuntimePolicyMgr(nil, nil, fakeversioned.NewSimpleClientset(), &fakeCompiler{}, notifier)
	if err != nil {
		t.Fatalf("NewRuntimePolicyMgr: %v", err)
	}
	t.Cleanup(m.queue.ShutDown)

	if len(notifier.handlers) != 1 {
		t.Fatalf("registered change handlers: got %d, want 1", len(notifier.handlers))
	}

	changed := svcRef("prod", "api")
	if err := m.rpInformer.GetIndexer().Add(netPolicy("referencing", networkBehavior(refRule(changed), nil))); err != nil {
		t.Fatal(err)
	}

	notifier.handlers[0](changed)

	if got := queuedNames(drainQueue(t, m)); !slices.Equal(got, []string{"referencing"}) {
		t.Fatalf("requeued policies: got %v, want [referencing]", got)
	}
}
