package egressmgr

import (
	"context"
	"slices"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/protofilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"k8s.io/apimachinery/pkg/labels"
)

// rpWithProtos builds an EvaluationResult carrying only a protocol pair.
func rpWithProtos(uid, mode string, sel map[string]string, allow, deny []string) *compiler.EvaluationResult {
	return &compiler.EvaluationResult{
		UID:       uid,
		Name:      uid,
		Mode:      mode,
		Selector:  labels.SelectorFromSet(labels.Set(sel)),
		Protocols: &compiler.AllowDenyPair{Allow: allow, Deny: deny},
	}
}

func wantLiveProtos(t *testing.T, f *fakeProtoFilter, allow, deny []string) {
	t.Helper()
	if !slices.Equal(f.liveAllow(), allow) {
		t.Errorf("live allow protocols: got %v, want %v", f.liveAllow(), allow)
	}
	if !slices.Equal(f.liveDeny(), deny) {
		t.Errorf("live deny protocols: got %v, want %v", f.liveDeny(), deny)
	}
}

func TestAttachPolicyProgramsProtocolTargets(t *testing.T) {
	e, _, _, _ := newTestManagerWithProto()
	addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rpWithProtos("rp-1", "enforce", webLabels, []string{"tls/h2", "http1"}, []string{"*", "ssh"}), events.EventTypeCreate)

	pf := protoFilterOf(t, e, "pod-1")
	wantLiveProtos(t, pf, []string{"http1", "tls/h2"}, []string{"ssh"})
	if !pf.defaultDeny {
		t.Error("protocol default deny flag not set for a deny list containing the star sentinel")
	}
	if !pf.observe {
		t.Error("protocol observe flag not set for a pod with an attached policy")
	}

	// the ip filter carries none of the protocol behavior's state
	f := filterOf(t, e, "pod-1")
	wantLiveIps(t, f, []string{}, []string{})
	wantDefaultDeny(t, f, false)
}

func TestProtocolAndNetworkDefaultDenyAreIndependent(t *testing.T) {
	e, _, _, _ := newTestManagerWithProto()
	addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-net", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)
	mustRpEvent(t, e, rpWithProtos("rp-proto", "enforce", webLabels, []string{"tls"}, []string{"*"}), events.EventTypeCreate)

	wantDefaultDeny(t, filterOf(t, e, "pod-1"), true)
	if !protoFilterOf(t, e, "pod-1").defaultDeny {
		t.Fatal("protocol default deny flag not set")
	}

	// removing the network policy must not clear the protocol filter's flag
	mustRpEvent(t, e, deleteEvent("rp-net"), events.EventTypeDelete)
	wantDefaultDeny(t, filterOf(t, e, "pod-1"), false)
	if !protoFilterOf(t, e, "pod-1").defaultDeny {
		t.Error("protocol default deny flag was cleared by an unrelated network policy delete")
	}

	mustRpEvent(t, e, deleteEvent("rp-proto"), events.EventTypeDelete)
	if protoFilterOf(t, e, "pod-1").defaultDeny {
		t.Error("protocol default deny flag survived the owning policy's delete")
	}
}

func TestRpUpdatedDiffsProtocolTargets(t *testing.T) {
	e, _, _, _ := newTestManagerWithProto()
	addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rpWithProtos("rp-1", "enforce", webLabels, []string{"tls/h2"}, []string{"*"}), events.EventTypeCreate)
	mustRpEvent(t, e, rpWithProtos("rp-1", "enforce", webLabels, []string{"tls/h2", "http1"}, nil), events.EventTypeUpdate)

	pf := protoFilterOf(t, e, "pod-1")
	wantLiveProtos(t, pf, []string{"http1", "tls/h2"}, []string{})
	if pf.defaultDeny {
		t.Error("protocol default deny flag survived the star sentinel leaving the deny list")
	}
}

func TestPodCreationProgramsExistingProtocolPolicies(t *testing.T) {
	e, _, _, _ := newTestManagerWithProto()
	mustRpEvent(t, e, rpWithProtos("rp-1", "enforce", webLabels, []string{"quic"}, []string{"*", "unknown"}), events.EventTypeCreate)
	addPod(t, e, "pod-1", webLabels, "/cg/pod-1")

	pf := protoFilterOf(t, e, "pod-1")
	wantLiveProtos(t, pf, []string{"quic"}, []string{"unknown"})
	if !pf.defaultDeny {
		t.Error("protocol default deny flag not set on a pod created after the policy")
	}
}

func TestObserveModePolicyProgramsNoProtocolTargets(t *testing.T) {
	e, _, _, _ := newTestManagerWithProto()
	addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rpWithProtos("rp-1", "monitor", webLabels, []string{"tls"}, []string{"*"}), events.EventTypeCreate)

	pf := protoFilterOf(t, e, "pod-1")
	wantLiveProtos(t, pf, []string{}, []string{})
	if pf.defaultDeny {
		t.Error("an observe-mode policy set the protocol default deny flag")
	}
	if !pf.observe {
		t.Error("protocol observe flag not set for an observe-mode policy")
	}
}

func TestProtoFilterAttachedToEveryPodCgroup(t *testing.T) {
	e, _, pff, _ := newTestManagerWithProto()
	addPod(t, e, "pod-1", webLabels, "/cg/a", "/cg/b")

	if len(pff.created) != 1 {
		t.Fatalf("proto filters created: got %d, want 1", len(pff.created))
	}
	got := slices.Clone(pff.created[0].attaches)
	slices.Sort(got)
	if !slices.Equal(got, []string{"/cg/a", "/cg/b"}) {
		t.Errorf("proto filter attaches: got %v, want [/cg/a /cg/b]", got)
	}
}

func TestCollectObservationsEmitsProtocolEvents(t *testing.T) {
	e, _, _, _ := newTestManagerWithProto()
	addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rpWithProtos("rp-1", "monitor", webLabels, nil, []string{"ssh"}), events.EventTypeCreate)

	pf := protoFilterOf(t, e, "pod-1")
	pf.protoEvents = map[protofilter.ProtoEventKey]uint32{
		{Protocol: "tls", ALPN: "h2", Decision: runtimeevent.DecisionAllow}: 3,
		{Protocol: "ssh", Decision: runtimeevent.DecisionDeny}:              2,
		{Protocol: "unknown", Decision: runtimeevent.DecisionAllow}:         1,
	}

	got, err := e.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations: unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("events: got %d (%v), want 3", len(got), got)
	}
	type want struct {
		protocol string
		alpn     string
		count    uint32
		denied   bool
	}
	wants := []want{
		{protocol: "ssh", count: 2, denied: true},
		{protocol: "tls", alpn: "h2", count: 3},
		{protocol: "unknown", count: 1},
	}
	for i, w := range wants {
		ev := got[i]
		if ev.Kind != runtimeevent.KindProtocol || ev.Protocol == nil {
			t.Fatalf("event %d: got kind %q facts %+v, want a protocol event", i, ev.Kind, ev.Protocol)
		}
		if ev.Protocol.Protocol != w.protocol || ev.Protocol.ALPN != w.alpn ||
			ev.Count != w.count || ev.KernelDenied != w.denied {
			t.Errorf("event %d: got {%s %s count=%d denied=%v}, want {%s %s count=%d denied=%v}",
				i, ev.Protocol.Protocol, ev.Protocol.ALPN, ev.Count, ev.KernelDenied,
				w.protocol, w.alpn, w.count, w.denied)
		}
		if ev.Pod.UID != "pod-1" {
			t.Errorf("event %d: pod uid = %q, want pod-1", i, ev.Pod.UID)
		}
	}
}

func TestTargetsConditionCoversProtocolValues(t *testing.T) {
	e, _, _, status := newTestManagerWithProto()

	mustRpEvent(t, e, rpWithProtos("rp-bad", "enforce", webLabels, []string{"grpc"}, nil), events.EventTypeCreate)
	cond, ok := status.latest("rp-bad", ConditionTargetsValid)
	if !ok || cond.Reason != ReasonUnsupportedTargets {
		t.Fatalf("condition for an unprogrammable protocol token: got %+v, want reason %s", cond, ReasonUnsupportedTargets)
	}

	mustRpEvent(t, e, rpWithProtos("rp-good", "enforce", webLabels, []string{"tls/h2"}, []string{"*"}), events.EventTypeCreate)
	cond, ok = status.latest("rp-good", ConditionTargetsValid)
	if !ok || cond.Reason != ReasonAllTargetsSupported {
		t.Fatalf("condition for supported protocol values: got %+v, want reason %s", cond, ReasonAllTargetsSupported)
	}
}
