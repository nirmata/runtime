package openexec

import "testing"

func TestAddPolicyAssignsDistinctSlots(t *testing.T) {
	d := &Dispatcher{dispatcherType: PROG_TYPE_LSM_OPEN}

	seen := make(map[uint32]struct{})
	for i := 0; i < maxPolicies; i++ {
		slot, err := d.AddPolicy()
		if err != nil {
			t.Fatalf("AddPolicy #%d: %v", i, err)
		}
		if _, dup := seen[slot]; dup {
			t.Fatalf("slot %d handed out twice", slot)
		}
		if slot >= maxPolicies {
			t.Fatalf("slot %d is outside the %d-bit mask", slot, maxPolicies)
		}
		seen[slot] = struct{}{}
	}
}

func TestAddPolicyRejectsFullDimension(t *testing.T) {
	d := &Dispatcher{dispatcherType: PROG_TYPE_LSM_OPEN}
	for i := 0; i < maxPolicies; i++ {
		if _, err := d.AddPolicy(); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := d.AddPolicy(); err == nil {
		t.Fatal("AddPolicy past capacity returned nil")
	}
}

func TestRemovePolicyFreesSlotForReuse(t *testing.T) {
	d := &Dispatcher{dispatcherType: PROG_TYPE_LSM_OPEN}
	first, err := d.AddPolicy()
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.AddPolicy()
	if err != nil {
		t.Fatal(err)
	}

	if err := d.RemovePolicy(first); err != nil {
		t.Fatal(err)
	}
	reused, err := d.AddPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if reused != first {
		t.Errorf("AddPolicy after RemovePolicy(%d) = %d, want the released slot", first, reused)
	}
	if reused == second {
		t.Errorf("released slot collided with live slot %d", second)
	}
}

func TestRemovePolicyUnknownSlot(t *testing.T) {
	d := &Dispatcher{dispatcherType: PROG_TYPE_LSM_OPEN}
	if err := d.RemovePolicy(3); err == nil {
		t.Error("RemovePolicy of a free slot returned nil")
	}
	if err := d.RemovePolicy(maxPolicies); err == nil {
		t.Error("RemovePolicy past the mask width returned nil")
	}
}
