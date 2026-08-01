package egressmgr

import (
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/events"
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
