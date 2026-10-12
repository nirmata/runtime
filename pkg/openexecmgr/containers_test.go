package openexecmgr

import (
	"slices"
	"testing"

	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/events"
)

func webPolicy(t *testing.T, h *harness) {
	t.Helper()
	if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
		nil, pair(nil, []string{"/usr/bin/curl"})), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
}

func TestContainerStartedCreatesUnknownPod(t *testing.T) {
	h := newHarness(t)
	webPolicy(t, h)

	if err := h.l.ContainerStarted(testPod("podA", map[string]string{"app": "web"}), nil, 11); err != nil {
		t.Fatal(err)
	}

	assertCgidCalls(t, "rpWeb exec AddCgids", h.enf("rpWeb", exec).addCgids, [][]uint64{{11}})
	if got := h.l.pods["podA"].cgids; !slices.Equal(got, []uint64{11}) {
		t.Errorf("stored cgids = %v, want [11]", got)
	}
	assertInvariant(t, h.l)
}

func TestContainerStartedAddsCgidToInformerPod(t *testing.T) {
	h := newHarness(t)
	webPolicy(t, h)
	pod := testPod("podA", map[string]string{"app": "web"})
	if err := h.l.PodEvent(pod, nil, cgs(11, 12), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	if err := h.l.ContainerStarted(pod, nil, 13); err != nil {
		t.Fatal(err)
	}

	assertCgidCalls(t, "rpWeb exec AddCgids", h.enf("rpWeb", exec).addCgids, [][]uint64{{11, 12}, {13}})
	if got := h.enf("rpWeb", exec).delCgids; len(got) != 0 {
		t.Errorf("DeleteCgids = %v, want none", got)
	}
	if got := h.l.pods["podA"].cgids; !slices.Equal(got, []uint64{11, 12, 13}) {
		t.Errorf("stored cgids = %v, want [11 12 13]", got)
	}
	assertInvariant(t, h.l)
}

func TestContainerStartedIgnoresKnownCgid(t *testing.T) {
	h := newHarness(t)
	webPolicy(t, h)
	pod := testPod("podA", map[string]string{"app": "web"})
	if err := h.l.PodEvent(pod, nil, cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	if err := h.l.ContainerStarted(pod, nil, 11); err != nil {
		t.Fatal(err)
	}

	assertCgidCalls(t, "rpWeb exec AddCgids", h.enf("rpWeb", exec).addCgids, [][]uint64{{11}})
	assertInvariant(t, h.l)
}

func TestInformerCreateAfterContainerStartedUpdatesPod(t *testing.T) {
	h := newHarness(t)
	webPolicy(t, h)
	pod := testPod("podA", map[string]string{"app": "web"})
	if err := h.l.ContainerStarted(pod, nil, 11); err != nil {
		t.Fatal(err)
	}

	if err := h.l.PodEvent(pod, nil, cgs(11, 12), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	assertCgidCalls(t, "rpWeb exec AddCgids", h.enf("rpWeb", exec).addCgids, [][]uint64{{11}, {12}})
	if got := h.l.pods["podA"].cgids; !slices.Equal(got, []uint64{11, 12}) {
		t.Errorf("stored cgids = %v, want [11 12]", got)
	}
	assertInvariant(t, h.l)
}
