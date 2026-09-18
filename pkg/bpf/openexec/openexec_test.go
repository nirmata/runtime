package openexec

import (
	"errors"
	"os"
	"testing"

	"github.com/nirmata/runtime/pkg/compiler"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
)

// newTestDispatcher backs a Dispatcher with a real open_entries map from the
// committed object, so the tests below assert on the exact bytes the kernel
// program reads.
func newTestDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create BPF maps")
	}

	spec, err := loadRuntimePolicy()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ebpf.NewMap(spec.Maps["open_entries"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { entries.Close() })

	return &Dispatcher{entries: entries, dispatcherType: PROG_TYPE_LSM_OPEN}
}

func newTestPolicy(t *testing.T, d *Dispatcher) *PolicyMap {
	t.Helper()
	logger := logr.Discard()
	p, err := NewPolicyMap(d, &logger)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// maskOf returns the slot mask stored under key, or 0 and false when no policy
// holds it.
func maskOf(t *testing.T, d *Dispatcher, key *runtimePolicyEntry) (uint64, bool) {
	t.Helper()
	var v uint64
	err := d.entries.Lookup(key, &v)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return 0, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return v, true
}

func TestPolicyMapSharedKeyHoldsBothSlotBits(t *testing.T) {
	d := newTestDispatcher(t)
	a, b := newTestPolicy(t, d), newTestPolicy(t, d)
	pair := &compiler.AllowDenyPair{Deny: []string{"/etc/shadow"}}

	for _, p := range []*PolicyMap{a, b} {
		if _, err := p.AddTargets(pair); err != nil {
			t.Fatal(err)
		}
	}

	key := pathEntry(dataTypeDeny, "/etc/shadow")
	if got, ok := maskOf(t, d, key); !ok || got != a.bit|b.bit {
		t.Fatalf("mask = %#x (present=%v), want %#x", got, ok, a.bit|b.bit)
	}

	if _, err := a.DeleteTargets(pair); err != nil {
		t.Fatal(err)
	}
	if got, ok := maskOf(t, d, key); !ok || got != b.bit {
		t.Fatalf("mask after one delete = %#x (present=%v), want %#x", got, ok, b.bit)
	}

	if _, err := b.DeleteTargets(pair); err != nil {
		t.Fatal(err)
	}
	if _, ok := maskOf(t, d, key); ok {
		t.Fatal("entry survived both policies deleting it")
	}
}

func TestPolicyMapCloseClearsEveryKeyItSet(t *testing.T) {
	d := newTestDispatcher(t)
	a, b := newTestPolicy(t, d), newTestPolicy(t, d)

	pair := &compiler.AllowDenyPair{Deny: []string{"/usr/lib/*"}, Allow: []string{"/bin/sh"}}
	if _, err := a.AddTargets(pair); err != nil {
		t.Fatal(err)
	}
	if err := a.AddCgids([]uint64{42}); err != nil {
		t.Fatal(err)
	}
	if err := a.SetDefaultDeny(true); err != nil {
		t.Fatal(err)
	}
	// b shares the cgroup, so that key must outlive a's Close with b's bit only
	if err := b.AddCgids([]uint64{42}); err != nil {
		t.Fatal(err)
	}

	slot := a.slot
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	for _, key := range []*runtimePolicyEntry{
		pathEntry(dataTypeDenyPrefix, "/usr/lib/"),
		pathEntry(dataTypeAllow, "/bin/sh"),
		{DataType: dataTypeFlags},
	} {
		if got, ok := maskOf(t, d, key); ok {
			t.Errorf("key %v still present after Close with mask %#x", key.DataType, got)
		}
	}
	if got, ok := maskOf(t, d, cgidEntry(42)); !ok || got != b.bit {
		t.Errorf("cgid mask after Close = %#x (present=%v), want %#x", got, ok, b.bit)
	}
	if d.slots&(1<<slot) != 0 {
		t.Errorf("slot %d still reserved after Close", slot)
	}
}

func TestPolicyMapClearingUnsetFlagLeavesOtherPolicyAlone(t *testing.T) {
	d := newTestDispatcher(t)
	a, b := newTestPolicy(t, d), newTestPolicy(t, d)

	if err := a.SetDefaultDeny(true); err != nil {
		t.Fatal(err)
	}
	if err := b.SetDefaultDeny(false); err != nil {
		t.Fatal(err)
	}

	if got, ok := maskOf(t, d, &runtimePolicyEntry{DataType: dataTypeFlags}); !ok || got != a.bit {
		t.Fatalf("flags mask = %#x (present=%v), want %#x", got, ok, a.bit)
	}
}
