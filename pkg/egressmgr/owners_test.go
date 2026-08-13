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

	wantPairs(t, "DeleteIps", f.deletes, []ipPair{pair([]string{"2.2.2.2"}, nil)})
	wantLiveIps(t, f, []string{"1.1.1.1", "3.3.3.3"}, []string{})
}

func TestSharedAddressGoesWhenTheLastOwnerDetaches(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)

	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)
	wantLiveIps(t, f, []string{"1.1.1.1"}, []string{})

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
	wantLiveIps(t, f, []string{"1.1.1.1", "2.2.2.2"}, []string{})
}

func TestOwnershipIsKeyedOnTheAddressNotItsSpelling(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, []string{"1.1.1.1/32"}, nil), events.EventTypeCreate)

	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)

	wantLiveIps(t, f, []string{"1.1.1.1"}, []string{})
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
