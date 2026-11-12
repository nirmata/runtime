package egressmgr

import (
	"testing"

	"github.com/nirmata/runtime/pkg/events"
)

func TestSharedAddressSurvivesOneOwnerDetaching(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1", "2.2.2.2"}, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, []string{"1.1.1.1", "3.3.3.3"}, nil), events.EventTypeCreate)
	f.reset()

	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)

	wantPairs(t, "DeleteIps", f.deletes, []ipPair{pair([]string{"2.2.2.2/32"}, nil)})
	wantLiveIps(t, f, []string{"1.1.1.1/32", "3.3.3.3/32"}, []string{})
}

func TestSharedAddressGoesWhenTheLastOwnerDetaches(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)

	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)
	wantLiveIps(t, f, []string{"1.1.1.1/32"}, []string{})

	mustRpEvent(t, e, deleteEvent("rp-2"), events.EventTypeDelete)
	wantLiveIps(t, f, []string{}, []string{})
}

// A resolved Service's addresses change on ordinary endpoint churn, so one
// policy dropping an address must not revoke another policy's claim on it.
func TestSharedAddressSurvivesAnotherPolicyDroppingIt(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1", "2.2.2.2"}, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)
	f.reset()

	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"2.2.2.2"}, nil), events.EventTypeUpdate)

	wantPairs(t, "DeleteIps", f.deletes, nil)
	wantLiveIps(t, f, []string{"1.1.1.1/32", "2.2.2.2/32"}, []string{})
}

func TestOwnershipIsKeyedOnTheAddressNotItsSpelling(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, []string{"1.1.1.1/32"}, nil), events.EventTypeCreate)

	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)

	wantLiveIps(t, f, []string{"1.1.1.1/32"}, []string{})
}

func TestSharedDomainSurvivesOneOwnerDetaching(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"api.example.com", "old.example.com"}, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, []string{"api.example.com", "cdn.example.com"}, nil), events.EventTypeCreate)
	f.reset()

	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)

	wantPairs(t, "DeleteIps", f.deletes, []ipPair{pair([]string{"old.example.com"}, nil)})
	wantLiveHosts(t, f, []string{"api.example.com", "cdn.example.com"}, []string{})
}

func TestSharedDomainGoesWhenTheLastOwnerDetaches(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"api.example.com"}, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, []string{"api.example.com"}, nil), events.EventTypeCreate)

	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)
	wantLiveHosts(t, f, []string{"api.example.com"}, []string{})

	mustRpEvent(t, e, deleteEvent("rp-2"), events.EventTypeDelete)
	wantLiveHosts(t, f, []string{}, []string{})
}

func TestSharedDomainSurvivesAnotherPolicyDroppingIt(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"api.example.com", "cdn.example.com"}, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, []string{"api.example.com"}, nil), events.EventTypeCreate)
	f.reset()

	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"cdn.example.com"}, nil), events.EventTypeUpdate)

	wantPairs(t, "DeleteIps", f.deletes, nil)
	wantLiveHosts(t, f, []string{"api.example.com", "cdn.example.com"}, []string{})
}

func TestDomainOwnershipIsKeyedOnTheNormalizedName(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"api.example.com"}, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, []string{"API.Example.COM."}, nil), events.EventTypeCreate)

	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)

	wantLiveHosts(t, f, []string{"api.example.com"}, []string{})
}

// the two sides are separate kernel maps, so one policy's allow claim must not
// hold up another policy's deny entry or the reverse.
func TestDomainOwnershipIsPerSide(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"api.example.com"}, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, nil, []string{"api.example.com"}), events.EventTypeCreate)

	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)

	wantLiveHosts(t, f, []string{}, []string{"api.example.com"})
}

// TestRespelledTargetSurvivesAnUpdate pins that an update which only changes
// how a target is written leaves it programmed. The update path claims the
// incoming values before releasing the outgoing ones, and both are keyed on the
// canonical target, so diffing the authored strings released the key the claim
// had just kept and deleted the entry: a respelled deny stopped being enforced.
func TestRespelledTargetSurvivesAnUpdate(t *testing.T) {
	tests := []struct {
		name      string
		from, to  []string
		wantIps   []string
		wantHosts []string
	}{
		{name: "ipv4 address to host prefix", from: []string{"1.2.3.4"}, to: []string{"1.2.3.4/32"}, wantIps: []string{"1.2.3.4/32"}},
		{name: "ipv4 host prefix to address", from: []string{"1.2.3.4/32"}, to: []string{"1.2.3.4"}, wantIps: []string{"1.2.3.4/32"}},
		{name: "ipv4 cidr host bits", from: []string{"10.0.0.0/8"}, to: []string{"10.1.2.3/8"}, wantIps: []string{"10.0.0.0/8"}},
		{name: "ipv4-mapped ipv6 address", from: []string{"1.2.3.4"}, to: []string{"::ffff:1.2.3.4"}, wantIps: []string{"1.2.3.4/32"}},
		{name: "ipv6 zero padding", from: []string{"2001:db8::1"}, to: []string{"2001:0db8::1"}, wantIps: []string{"2001:db8::1/128"}},
		{name: "ipv6 address to host prefix", from: []string{"2001:db8::1"}, to: []string{"2001:db8:0:0:0:0:0:1/128"}, wantIps: []string{"2001:db8::1/128"}},
		{name: "ipv6 cidr host bits", from: []string{"2001:db8::/32"}, to: []string{"2001:db8:ffff::/32"}, wantIps: []string{"2001:db8::/32"}},
		{name: "hostname case", from: []string{"api.example.com"}, to: []string{"API.Example.COM"}, wantHosts: []string{"api.example.com"}},
		{name: "hostname root dot", from: []string{"api.example.com"}, to: []string{"api.example.com."}, wantHosts: []string{"api.example.com"}},
		{name: "duplicate spelling dropped", from: []string{"1.2.3.4", "1.2.3.4/32"}, to: []string{"1.2.3.4/32"}, wantIps: []string{"1.2.3.4/32"}},
		{name: "unsupported value carried along", from: []string{"*.example.com", "1.2.3.4"}, to: []string{"*.example.com", "1.2.3.4/32"}, wantIps: []string{"1.2.3.4/32"}},
	}
	for _, tt := range tests {
		wantIps, wantHosts := tt.wantIps, tt.wantHosts
		if wantIps == nil {
			wantIps = []string{}
		}
		if wantHosts == nil {
			wantHosts = []string{}
		}
		t.Run(tt.name+"/allow", func(t *testing.T) {
			e, _, _ := newTestManager()
			f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
			mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, tt.from, nil), events.EventTypeCreate)
			f.reset()

			mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, tt.to, nil), events.EventTypeUpdate)

			wantPairs(t, "AddIps", f.adds, nil)
			wantPairs(t, "DeleteIps", f.deletes, nil)
			wantLiveIps(t, f, wantIps, []string{})
			wantLiveHosts(t, f, wantHosts, []string{})
		})
		t.Run(tt.name+"/deny", func(t *testing.T) {
			e, _, _ := newTestManager()
			f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
			mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, nil, tt.from), events.EventTypeCreate)
			f.reset()

			mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, nil, tt.to), events.EventTypeUpdate)

			wantPairs(t, "AddIps", f.adds, nil)
			wantPairs(t, "DeleteIps", f.deletes, nil)
			wantLiveIps(t, f, []string{}, wantIps)
			wantLiveHosts(t, f, []string{}, wantHosts)
		})
	}
}

// A respelled target must still be released once nothing names it: the claim
// the update kept is the one the eventual delete has to drop.
func TestRespelledTargetGoesWhenThePolicyIsDeleted(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, nil, []string{"2001:db8::1", "api.example.com"}), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, nil, []string{"2001:0db8::1", "API.example.com."}), events.EventTypeUpdate)

	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)

	wantLiveIps(t, f, []string{}, []string{})
	wantLiveHosts(t, f, []string{}, []string{})
}

// A target that changes meaning, not spelling, is still swapped: canonical
// comparison must not mistake a different prefix length for the same target.
func TestChangedPrefixLengthIsReprogrammed(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, nil, []string{"10.0.0.0/8"}), events.EventTypeCreate)
	f.reset()

	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, nil, []string{"10.0.0.0/16"}), events.EventTypeUpdate)

	wantPairs(t, "DeleteIps", f.deletes, []ipPair{pair(nil, []string{"10.0.0.0/8"})})
	wantLiveIps(t, f, []string{}, []string{"10.0.0.0/16"})
}

func TestRespelledProtocolTargetSurvivesAnUpdate(t *testing.T) {
	tests := []struct {
		name     string
		from, to string
		want     string
	}{
		{name: "padded protocol", from: "ssh", to: " ssh ", want: "ssh"},
		{name: "quoted alpn", from: "tls/h2", to: `"tls/h2"`, want: "tls/h2"},
		{name: "bracketed protocol", from: "http/1.1", to: "[http/1.1]", want: "http/1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/allow", func(t *testing.T) {
			e, _, _, _ := newTestManagerWithProto()
			addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
			mustRpEvent(t, e, rpWithProtos("rp-1", "enforce", webLabels, []string{tt.from}, nil), events.EventTypeCreate)
			pf := protoFilterOf(t, e, "pod-1")
			pf.adds, pf.deletes = nil, nil

			mustRpEvent(t, e, rpWithProtos("rp-1", "enforce", webLabels, []string{tt.to}, nil), events.EventTypeUpdate)

			wantPairs(t, "AddProtocols", pf.adds, nil)
			wantPairs(t, "DeleteProtocols", pf.deletes, nil)
			wantLiveProtos(t, pf, []string{tt.want}, []string{})
		})
		t.Run(tt.name+"/deny", func(t *testing.T) {
			e, _, _, _ := newTestManagerWithProto()
			addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
			mustRpEvent(t, e, rpWithProtos("rp-1", "enforce", webLabels, nil, []string{tt.from}), events.EventTypeCreate)
			pf := protoFilterOf(t, e, "pod-1")
			pf.adds, pf.deletes = nil, nil

			mustRpEvent(t, e, rpWithProtos("rp-1", "enforce", webLabels, nil, []string{tt.to}), events.EventTypeUpdate)

			wantPairs(t, "AddProtocols", pf.adds, nil)
			wantPairs(t, "DeleteProtocols", pf.deletes, nil)
			wantLiveProtos(t, pf, []string{}, []string{tt.want})
		})
	}
}
