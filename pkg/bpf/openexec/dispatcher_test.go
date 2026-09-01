package openexec

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const testSlots = 4

func newTestDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create BPF maps")
	}

	progArray, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: testSlots,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { progArray.Close() })

	progCount, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { progCount.Close() })

	return &Dispatcher{
		progArray:      progArray,
		progCount:      progCount,
		progCountKey:   1,
		progIdx:        make(map[int]uint32),
		dispatcherType: PROG_TYPE_LSM_OPEN,
	}
}

// a prog array only accepts fds of loadable programs, so each test enforcer is
// a real (never attached) program that returns 0.
func newTestProgram(t *testing.T) int {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { prog.Close() })
	return prog.FD()
}

func count(t *testing.T, d *Dispatcher) uint8 {
	t.Helper()
	var pc uint8
	if err := d.progCount.Lookup(&d.progCountKey, &pc); err != nil {
		t.Fatal(err)
	}
	return pc
}

func slotOccupied(t *testing.T, d *Dispatcher, idx uint32) bool {
	t.Helper()
	var id uint32
	err := d.progArray.Lookup(&idx, &id)
	if err == nil {
		return true
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false
	}
	t.Fatal(err)
	return false
}

func TestAddPolicyPublishesSlotAndCount(t *testing.T) {
	d := newTestDispatcher(t)
	fd := newTestProgram(t)

	if err := d.AddPolicy(fd); err != nil {
		t.Fatal(err)
	}

	idx, ok := d.progIdx[fd]
	if !ok {
		t.Fatalf("fd %d missing from progIdx", fd)
	}
	if !slotOccupied(t, d, idx) {
		t.Errorf("prog array slot %d is empty", idx)
	}
	if got := count(t, d); got != 1 {
		t.Errorf("prog_count = %d, want 1", got)
	}
}

func TestAddPolicyAssignsDistinctSlots(t *testing.T) {
	d := newTestDispatcher(t)

	seen := make(map[uint32]int)
	for i := 0; i < testSlots; i++ {
		fd := newTestProgram(t)
		if err := d.AddPolicy(fd); err != nil {
			t.Fatal(err)
		}
		idx := d.progIdx[fd]
		if other, dup := seen[idx]; dup {
			t.Fatalf("fds %d and %d both landed in slot %d", other, fd, idx)
		}
		seen[idx] = fd
	}

	if got := count(t, d); got != testSlots {
		t.Errorf("prog_count = %d, want %d", got, testSlots)
	}
}

func TestAddPolicyRejectsFullArray(t *testing.T) {
	d := newTestDispatcher(t)
	for i := 0; i < testSlots; i++ {
		if err := d.AddPolicy(newTestProgram(t)); err != nil {
			t.Fatal(err)
		}
	}

	extra := newTestProgram(t)
	if err := d.AddPolicy(extra); err == nil {
		t.Fatal("AddPolicy past capacity returned nil")
	}
	if _, ok := d.progIdx[extra]; ok {
		t.Error("rejected fd was recorded in progIdx")
	}
	if got := count(t, d); got != testSlots {
		t.Errorf("prog_count = %d, want %d", got, testSlots)
	}
}

// A count that cannot be bumped leaves a program published in the array that
// the chain would never reach; AddPolicy has to take the slot back.
func TestAddPolicyRollsBackSlotWhenCountFails(t *testing.T) {
	d := newTestDispatcher(t)
	saturated := uint8(testSlots)
	if err := d.progCount.Update(&d.progCountKey, &saturated, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	fd := newTestProgram(t)
	if err := d.AddPolicy(fd); err == nil {
		t.Fatal("AddPolicy with a saturated count returned nil")
	}
	if _, ok := d.progIdx[fd]; ok {
		t.Error("failed fd was recorded in progIdx")
	}
	if slotOccupied(t, d, 0) {
		t.Error("prog array slot 0 still holds the rolled-back program")
	}
}

func TestDeleteProgramClearsSlotAndCount(t *testing.T) {
	d := newTestDispatcher(t)
	fd := newTestProgram(t)
	if err := d.AddPolicy(fd); err != nil {
		t.Fatal(err)
	}
	idx := d.progIdx[fd]

	if err := d.DeleteProgram(fd); err != nil {
		t.Fatal(err)
	}
	if slotOccupied(t, d, idx) {
		t.Errorf("prog array slot %d still occupied", idx)
	}
	if got := count(t, d); got != 0 {
		t.Errorf("prog_count = %d, want 0", got)
	}
	if _, ok := d.progIdx[fd]; ok {
		t.Error("deleted fd is still in progIdx")
	}
}

func TestDeleteProgramUnknownFd(t *testing.T) {
	d := newTestDispatcher(t)
	fd := newTestProgram(t)
	if err := d.AddPolicy(fd); err != nil {
		t.Fatal(err)
	}

	if err := d.DeleteProgram(fd + 1000); err == nil {
		t.Fatal("DeleteProgram of an unregistered fd returned nil")
	}
	if got := count(t, d); got != 1 {
		t.Errorf("prog_count = %d, want 1", got)
	}
}

func TestDeleteProgramToleratesEmptySlot(t *testing.T) {
	d := newTestDispatcher(t)
	fd := newTestProgram(t)
	if err := d.AddPolicy(fd); err != nil {
		t.Fatal(err)
	}
	idx := d.progIdx[fd]
	if err := d.progArray.Delete(&idx); err != nil {
		t.Fatal(err)
	}

	if err := d.DeleteProgram(fd); err != nil {
		t.Fatalf("DeleteProgram on an already empty slot: %v", err)
	}
	if got := count(t, d); got != 0 {
		t.Errorf("prog_count = %d, want 0", got)
	}
}

func TestFreeSlotReusesReleasedSlot(t *testing.T) {
	d := newTestDispatcher(t)
	first := newTestProgram(t)
	second := newTestProgram(t)
	if err := d.AddPolicy(first); err != nil {
		t.Fatal(err)
	}
	if err := d.AddPolicy(second); err != nil {
		t.Fatal(err)
	}
	released := d.progIdx[first]
	if err := d.DeleteProgram(first); err != nil {
		t.Fatal(err)
	}

	idx, err := d.freeSlot()
	if err != nil {
		t.Fatal(err)
	}
	if idx != released {
		t.Errorf("freeSlot() = %d, want the released slot %d", idx, released)
	}
}

func TestFreeSlotRejectsFullArray(t *testing.T) {
	d := newTestDispatcher(t)
	for i := 0; i < testSlots; i++ {
		if err := d.AddPolicy(newTestProgram(t)); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := d.freeSlot(); err == nil {
		t.Fatal("freeSlot() on a full array returned nil")
	}
}

func TestBumpCount(t *testing.T) {
	tests := []struct {
		name    string
		start   uint8
		delta   int
		want    uint8
		wantErr bool
	}{
		{name: "increment", start: 0, delta: 1, want: 1},
		{name: "decrement", start: 2, delta: -1, want: 1},
		{name: "to capacity", start: testSlots - 1, delta: 1, want: testSlots},
		{name: "underflow is rejected", start: 0, delta: -1, want: 0, wantErr: true},
		{name: "overflow is rejected", start: testSlots, delta: 1, want: testSlots, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestDispatcher(t)
			if err := d.progCount.Update(&d.progCountKey, &tt.start, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}

			err := d.bumpCount(tt.delta)
			if (err != nil) != tt.wantErr {
				t.Fatalf("bumpCount(%d) error = %v, wantErr %v", tt.delta, err, tt.wantErr)
			}
			if got := count(t, d); got != tt.want {
				t.Errorf("prog_count = %d, want %d", got, tt.want)
			}
		})
	}
}

// The prog_count array is shared across hooks, so a dispatcher must only ever
// move its own key.
func TestBumpCountLeavesOtherHooksAlone(t *testing.T) {
	d := newTestDispatcher(t)
	other := &Dispatcher{
		progArray:      d.progArray,
		progCount:      d.progCount,
		progCountKey:   d.progCountKey + 1,
		progIdx:        make(map[int]uint32),
		dispatcherType: PROG_TYPE_LSM_EXEC,
	}
	if err := other.bumpCount(2); err != nil {
		t.Fatal(err)
	}

	if err := d.bumpCount(1); err != nil {
		t.Fatal(err)
	}
	if got := count(t, d); got != 1 {
		t.Errorf("own prog_count = %d, want 1", got)
	}
	if got := count(t, other); got != 2 {
		t.Errorf("other prog_count = %d, want 2", got)
	}
}
