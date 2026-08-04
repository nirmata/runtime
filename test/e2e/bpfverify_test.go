package e2e_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/cilium/ebpf"
)

// bpfObjectSpec is one committed BPF object in the verifier lane. A new source
// joins the lane by appending a literal to bpfObjects; no workflow file changes,
// and TestBPFVerifyEveryObjectIsRegistered fails on any object that does not.
type bpfObjectSpec struct {
	// object is the repo-relative path of the little-endian object. The
	// big-endian twin is covered by `make verify-bpf`, which recompiles both.
	object string
	progs  []progCheck
	// pre is nil for a program the kernel loads without an opt-in feature.
	pre *precondition
}

type progCheck struct {
	name string
	// typ and attach are read from the SEC name as bpf2go parsed it, before the
	// lane touches the spec, so they catch a SEC rename in the C.
	typ    ebpf.ProgramType
	attach ebpf.AttachType
	// attachTo names the kernel hook for a program whose SEC name is not one.
	// The LSM object is SEC("lsm/generic_handler"); "generic_handler" is not a
	// hook, so the loader chooses file_open or bprm_check_security and the lane
	// has to choose the same way. Empty means the SEC name already resolves.
	attachTo string
	// insnBudget fails the check when the verifier walks more instructions than
	// this. The count is logged either way: a regression should show up as a
	// number that moved, not only as a threshold that tripped.
	insnBudget uint32
}

var bpfObjects = []bpfObjectSpec{
	{
		object: "pkg/bpf/egressfilter/egressblock_bpfel.o",
		progs: []progCheck{{
			name:       "cgroup_egress",
			typ:        ebpf.CGroupSKB,
			attach:     ebpf.AttachCGroupInetEgress,
			insnBudget: 1000,
		}, {
			name:   "cgroup_dns_ingress",
			typ:    ebpf.CGroupSKB,
			attach: ebpf.AttachCGroupInetIngress,
			// The DNS parser's unrolled label and answer walks put this two
			// orders of magnitude above the egress program: ~15.3k processed,
			// on both a 6.12 arm64 kernel and the amd64 runner.
			insnBudget: 32000,
		}},
	},
	{
		object: "pkg/bpf/lsm/lsmfileopen_bpfel.o",
		pre:    needBPFLSM,
		progs: []progCheck{{
			name:       "generic_lsm_handler",
			typ:        ebpf.LSM,
			attach:     ebpf.AttachLSMMac,
			attachTo:   "file_open",
			insnBudget: 2000,
		}},
	},
	{
		object: "pkg/bpf/lsm/lsmexeccheck_bpfel.o",
		pre:    needBPFLSM,
		progs: []progCheck{{
			name:       "generic_lsm_handler",
			typ:        ebpf.LSM,
			attach:     ebpf.AttachLSMMac,
			attachTo:   "bprm_check_security",
			insnBudget: 2000,
		}},
	},
	{
		// The budget is an order of magnitude above the other objects because the
		// question name is read by an unrolled per-byte pass. It needs no
		// precondition: a cgroup_skb program loads on any kernel this project
		// supports.
		object: "pkg/bpf/dnsquery/dnsquery_bpfel.o",
		progs: []progCheck{{
			name:       "cgroup_dns_egress",
			typ:        ebpf.CGroupSKB,
			attach:     ebpf.AttachCGroupInetEgress,
			insnBudget: 13000,
		}},
	},
}

// precondition answers three ways, and the third is the point: "I could not
// read the LSM list" is not "the kernel has no BPF-LSM". Folding them sends the
// reader to a boot-parameter fix for what is usually an unmounted securityfs.
type precondition struct {
	name string
	// requireEnv, set to "1", turns this precondition's skip into a failure. A
	// lane that guarantees the feature sets it so a runner that silently lost
	// the feature reports red instead of green.
	requireEnv string
	// evaluate returns (true, "", nil) when satisfied, (false, reason, nil)
	// when the host answered no, and (false, "", err) when it could not answer.
	evaluate func() (bool, string, error)
}

var needBPFLSM = &precondition{
	name:       "BPF-LSM",
	requireEnv: "NIRMATA_RUNTIME_REQUIRE_BPF_LSM",
	evaluate: func() (bool, string, error) {
		on, err := utils.BpfLSMEnabled()
		if err != nil {
			return false, "", err
		}
		if !on {
			return false, "kernel not booted with BPF-LSM ('bpf' absent from /sys/kernel/security/lsm); " +
				"boot it with lsm=...,bpf", nil
		}
		return true, "", nil
	},
}

// TestBPFVerify loads every committed BPF object into the running kernel. Load
// is where the verifier runs, so a program the verifier rejects fails here with
// its full log; nothing is attached and no map is written.
func TestBPFVerify(t *testing.T) {
	requireLittleEndianHost(t)
	requireBPFCapableHost(t)

	root := repoRoot(t)
	loaded := 0
	var skips []string

	for _, obj := range bpfObjects {
		t.Run(obj.object, func(t *testing.T) {
			if obj.pre != nil {
				required := os.Getenv(obj.pre.requireEnv) == "1"
				ok, reason, err := obj.pre.evaluate()
				switch {
				case err != nil && required:
					t.Fatalf("%s=1 but whether %s is available could not be determined: %v",
						obj.pre.requireEnv, obj.pre.name, err)
				case err != nil:
					// Indeterminate: the host could not answer. Never reported
					// as unsatisfied.
					skips = append(skips, fmt.Sprintf("%s: %s indeterminate: %v", obj.object, obj.pre.name, err))
					t.Skipf("cannot determine whether %s is available: %v", obj.pre.name, err)
				case !ok && required:
					t.Fatalf("%s=1 but %s is unavailable: %s", obj.pre.requireEnv, obj.pre.name, reason)
				case !ok:
					skips = append(skips, fmt.Sprintf("%s: %s unsatisfied: %s", obj.object, obj.pre.name, reason))
					t.Skipf("%s unavailable: %s", obj.pre.name, reason)
				}
			}
			verifyObject(t, filepath.Join(root, obj.object), obj.progs)
			loaded++
		})
	}

	t.Logf("loaded=%d skipped=%d", loaded, len(skips))
	for _, s := range skips {
		t.Logf("skipped %s", s)
	}
	if loaded == 0 {
		t.Fatal("no BPF object was loaded: the lane asserted nothing")
	}
}

func verifyObject(t *testing.T, path string, progs []progCheck) {
	t.Helper()

	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	for _, p := range progs {
		ps := spec.Programs[p.name]
		if ps == nil {
			t.Fatalf("%s has no program %q (present: %v)", path, p.name, programNames(spec))
		}
		if ps.Type != p.typ {
			t.Errorf("program %q type = %v, want %v (SEC name changed?)", p.name, ps.Type, p.typ)
		}
		if ps.AttachType != p.attach {
			t.Errorf("program %q attach type = %v, want %v (SEC name changed?)", p.name, ps.AttachType, p.attach)
		}
		if p.attachTo != "" {
			ps.AttachTo = p.attachTo
		}
	}
	if t.Failed() {
		return
	}

	// A map-of-maps carries its inner map as an ELF "entry" at key 0. That is a
	// template, not data, and cilium/ebpf cannot marshal it as a key; the
	// production loaders drop it as well. Nothing here verifies map contents.
	for _, m := range spec.Maps {
		if m.Type == ebpf.HashOfMaps || m.Type == ebpf.ArrayOfMaps {
			m.Contents = nil
		}
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// %+v renders *ebpf.VerifierError's full log, which is the whole
		// reason this lane exists.
		t.Fatalf("loading %s: %+v", path, err)
	}
	defer coll.Close()

	for _, p := range progs {
		prog := coll.Programs[p.name]
		info, err := prog.Info()
		if err != nil {
			t.Errorf("program %q info: %v", p.name, err)
			continue
		}
		insns, ok := info.VerifiedInstructions()
		if !ok {
			t.Logf("program %q loaded (verified_insns unavailable on this kernel)", p.name)
			continue
		}
		t.Logf("program %q loaded: verified_insns=%d budget=%d", p.name, insns, p.insnBudget)
		if insns > p.insnBudget {
			t.Errorf("program %q verified_insns = %d, over the budget of %d", p.name, insns, p.insnBudget)
		}
	}
}

// TestBPFVerifyEveryObjectIsRegistered needs neither root nor Linux, so an
// unregistered object breaks `go test ./...` on a laptop rather than waiting
// for the kernel-bound lane to not run it.
func TestBPFVerifyEveryObjectIsRegistered(t *testing.T) {
	root := repoRoot(t)

	found, err := filepath.Glob(filepath.Join(root, "pkg", "bpf", "*", "*_bpfel.o"))
	if err != nil {
		t.Fatalf("globbing committed objects: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("no pkg/bpf/*/*_bpfel.o found: the glob no longer matches the tree layout")
	}

	registered := make([]string, 0, len(bpfObjects))
	for _, obj := range bpfObjects {
		registered = append(registered, obj.object)
		if _, err := os.Stat(filepath.Join(root, obj.object)); err != nil {
			t.Errorf("bpfObjects names %s, which does not exist: %v", obj.object, err)
		}
		if len(obj.progs) == 0 {
			t.Errorf("bpfObjects entry %s lists no programs", obj.object)
		}
		// Registering the object is not enough: a second program added to an
		// object already in the table would otherwise never be loaded here.
		spec, err := ebpf.LoadCollectionSpec(filepath.Join(root, obj.object))
		if err != nil {
			t.Errorf("loading %s to enumerate its programs: %v", obj.object, err)
			continue
		}
		for name := range spec.Programs {
			if !slices.ContainsFunc(obj.progs, func(p progCheck) bool { return p.name == name }) {
				t.Errorf("%s contains program %q with no entry in bpfObjects "+
					"(test/e2e/bpfverify_test.go): add one so the verifier lane loads it",
					obj.object, name)
			}
		}
	}

	for _, path := range found {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatalf("relativizing %s: %v", path, err)
		}
		rel = filepath.ToSlash(rel)
		if !slices.Contains(registered, rel) {
			t.Errorf("%s has no entry in bpfObjects (test/e2e/bpfverify_test.go): "+
				"add one so the verifier lane loads it", rel)
		}
	}
}

func programNames(spec *ebpf.CollectionSpec) []string {
	names := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// requireLittleEndianHost gates the lane on the objects it can actually load.
// The _bpfeb twins are never loaded anywhere; `make verify-bpf` recompiles both
// endiannesses and is what keeps them honest.
func requireLittleEndianHost(t *testing.T) {
	t.Helper()
	var probe [2]byte
	binary.NativeEndian.PutUint16(probe[:], 1)
	if probe[0] != 1 {
		t.Skip("verifier lane loads the committed _bpfel objects; host is big-endian")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving the repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("%s does not look like the repo root: %v", root, err)
	}
	return root
}
